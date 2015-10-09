/*  
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "denser.h"
#include "internal.h"
#include "event.h"
#include "argcargv.h"
#include "timeval.h"
#include "bprint.h"

extern struct event	eventlist[ 32 ];

/*
 * dnsr_result waits upto timeout for a result from a previous
 * query.  If timeout is NULL, dnsr_result will block, if timeout is
 * 0, dnsr_result will poll.  Non-null timeout is modified on return
 * with the amount of time elapsed.
 */

    struct dnsr_result * 
dnsr_result( DNSR *dnsr, struct timeval *timeout )
{
    char		resp[ DNSR_MAX_UDP ];
    char		*resp_tcp = NULL;
    int			rc, error, resplen, resp_errno = DNSR_ERROR_NONE;
    int                 fd;
    fd_set		fdset;
    struct dnsr_result	*result = NULL;
    struct timeval	cur;	/* Current time */
    struct timeval	end;	/* Time of timeout */
    struct timeval	ext;	/* Time passed since last query */	
    struct timeval	wait;	/* Calculated wait time */
    struct sockaddr_storage	reply_from; 
    socklen_t 		socklen;

    if ( !dnsr ) {
        return( NULL );
    }

    if ( !dnsr->d_querysent ) {
	DEBUG( fprintf( stderr, "dnsr_result: query not sent\n" ));
	dnsr->d_errno = DNSR_ERROR_NO_QUERY;
	return( NULL );
    }
    socklen = sizeof( struct sockaddr_storage );

    /* Calculate end */
    if ( timeout != NULL ) {
	if ( gettimeofday( &cur, NULL ) < 0 ) {
	    DEBUG( perror( "gettimeofday" ));
	    dnsr->d_errno = DNSR_ERROR_SYSTEM;
	    return( NULL );
	}
	if ( tv_add( &cur, timeout, &end) != 0 ) {
	    DEBUG( fprintf( stderr, "tv_add failed\n" ));
	    dnsr->d_errno = DNSR_ERROR_TV;
	    return( NULL );
	}
    }

    memset( &resp, 0, DNSR_MAX_UDP );

    while ( eventlist[ dnsr->d_state ].e_type != DNSR_STATE_DONE ) {
        error = 0;

	switch( eventlist[ dnsr->d_state ].e_type ) {

	case DNSR_STATE_WAIT:

	    /* Convert wait event value into timeval struct */
	    DEBUG( fprintf( stderr, "WAIT_STATE\n" ));
	    wait.tv_sec = eventlist[ dnsr->d_state ].e_value;
	    wait.tv_usec = 0;
	    DEBUG( fprintf( stderr, "event time: %ld.%ld\n",
		(long int)wait.tv_sec, (long int)wait.tv_usec ));

	    /* Get current time */
	    if ( gettimeofday( &cur, NULL ) < 0 ) {
		DEBUG( perror( "gettimeofday" ));
		dnsr->d_errno = DNSR_ERROR_SYSTEM;
		return( NULL );
	    }

	    /* Adjust wait to account for pass*/
	    if ( tv_sub( &cur, &dnsr->d_querytime, &ext ) < 0 ) {
		DEBUG( fprintf( stderr, "tv_sub failed\n" ));
		dnsr->d_errno = DNSR_ERROR_TV;
		return( NULL );
	    }
	    DEBUG( fprintf( stderr, "ext time: %ld.%06ld\n",
		(long int)ext.tv_sec, (long int)ext.tv_usec ));

	    if ( tv_sub( &wait, &ext, &wait ) < 0 ) {
		/* wait is negative, we can't have that */
		/* Why can't I just say wait = {0,0} */
		wait.tv_sec = 0;
		wait.tv_usec = 0;
	    }
	    DEBUG( fprintf( stderr, "ext adjusted time: %ld.%ld\n",
		(long int)wait.tv_sec, (long int)wait.tv_usec ));

	    /* Check endtime and make sure we never wait past it */
	    if ( timeout != NULL ) {
		if ( tv_sub( &end, &cur, timeout ) != 0 ) {
		    /* timedout - but let's check an answer one last time */
		    wait.tv_sec = 0;
		    wait.tv_usec = 0;
		} else {
		    if ( tv_gt( &wait, timeout )) {
			/* The end is near; wait for it, but no longer */
			wait.tv_sec = timeout->tv_sec;
			wait.tv_usec = timeout->tv_usec;
		    }
		}
	    }

	    DEBUG( fprintf( stderr, "select time: %ld.%ld\n", (long)wait.tv_sec,
		    (long)wait.tv_usec ));
	    /*
	     * "On successful completion,  the  object  pointed  to  by  the
	     * timeout argument may be modified" so we don't know how
	     * much time has passed when we return.  ( select(3c) )
	     *
	     * To look for error we could:
	     *   1 - use errorfds to get error condition
	     *   2 - look at result, if any, to see if it's good
	     *
	     * In either case, we could select again on same NS if it is just
	     * a temp error, or mark is down if it is fatal.
	     */
	    FD_ZERO( &fdset );
            if ( dnsr->d_fd >= 0 ) {
	        FD_SET( dnsr->d_fd, &fdset );
            }
            if ( dnsr->d_fd6 >= 0 ) {
                FD_SET( dnsr->d_fd6, &fdset );
            }
	    if (( rc = select(
                    (dnsr->d_fd > dnsr->d_fd6 ? dnsr->d_fd : dnsr->d_fd6 ) + 1,
                    &fdset, NULL, NULL, &wait )) < 0 ) {
		DEBUG( perror( "select" ));
		dnsr->d_errno = DNSR_ERROR_SYSTEM;
		return( NULL );
	    } else if ( rc == 0 ) {
		/* Break out of wait state */
		DEBUG( fprintf( stderr, "dnsr_result: select timed out\n" ));
		DEBUG( fprintf( stderr, "advancing state\n" ));
		dnsr->d_state++;
		break;
	    }

            if ( FD_ISSET( dnsr->d_fd6, &fdset )) {
                fd = dnsr->d_fd6;
            } else if ( FD_ISSET( dnsr->d_fd, &fdset )) {
                fd = dnsr->d_fd;
            } else {
		DEBUG( fprintf( stderr, "select: wrong fd\n" ));
		/* XXX - error value? */
		dnsr->d_errno = DNSR_ERROR_FD_SET;
		return( NULL );
	    }
	    /* Get response */

	    /* XXX - OS X doesn't have socklen_t */
	    if (( resplen = recvfrom( fd, &resp, DNSR_MAX_UDP, 0,
		    (struct sockaddr *)&reply_from, &socklen )) < 0 ) {
		DEBUG( perror( "recvfrom" ));
		dnsr->d_errno = DNSR_ERROR_SYSTEM;
		return( NULL );
	    }
	    DEBUG( fprintf( stderr, "received %d bytes\n", resplen ));
	    DEBUG( {  
                char                        buf[ INET6_ADDRSTRLEN ];
                if ( getnameinfo( (struct sockaddr*)&reply_from,
                        sizeof( struct sockaddr_storage ), buf,
                        INET6_ADDRSTRLEN, NULL, 0, NI_NUMERICHOST ) == 0 ) {
		    fprintf( stderr, "reply: %s\n", buf );
                }
	    } )

	    if (( rc = dnsr_validate_resp( dnsr, resp,
                    (struct sockaddr *)&reply_from )) != 0 ) {
		DEBUG( dnsr_perror( dnsr, "dnsr_validate_resp" ));
                if ( rc == DNSR_ERROR_NS_INVALID ) {
                    break;
		} else if ( rc == DNSR_ERROR_TRUNCATION ) {
		    if ((( resp_tcp = dnsr_send_query_tcp( dnsr,
			    dnsr->d_nsresp, &resplen )) == NULL )) {
			return( NULL );
		    }
		    if (( dnsr_validate_resp( dnsr, resp_tcp,
			    (struct sockaddr *)&reply_from )) != 0 ) {
                        error = 1;        
		    }

		} else {
                    error = 1;
		}
	    }

	    if ( resp_tcp != NULL ) {
		result = dnsr_create_result( dnsr, resp_tcp, resplen );
	    } else {
		result = dnsr_create_result( dnsr, resp, resplen );
	    }
	    if ( result == NULL ) {
		if( dnsr->d_errno == DNSR_ERROR_SYSTEM ) {
		    DEBUG( fprintf( stderr, "create_result failed\n" ));
		    free( resp_tcp );
		    resp_tcp = NULL;
		    return( NULL );
		} else {
		    /* Bad result - goto top of loop, but save error */
		    free( resp_tcp );
		    resp_tcp = NULL;
		    resp_errno = dnsr->d_errno;
		    dnsr->d_errno = DNSR_ERROR_NONE;
		    break;
		}
	    } else {
		free( resp_tcp );
		resp_tcp = NULL;
	    }
            if (( rc = dnsr_validate_result( dnsr, result )) != 0 ) {
                DEBUG( fprintf( stderr, "dnsr_validate_result failed\n" ));
                if ( rc == DNSR_ERROR_NAME ) {
                    return( result );
                }
                error = 1;
            }
	    if ( dnsr_match_additional( dnsr, result ) != 0 ) {
		DEBUG( fprintf( stderr, "dnsr_match_additional failed\n" ));
		dnsr_free_result( result );
		return( NULL );
	    }
            if ( error == 1 ) {
                dnsr_free_result( result );
                break;
            }
	    return( result );

	case DNSR_STATE_ASK:
	    DEBUG( fprintf( stderr, "ASK_STATE\n" ));
	    if ( eventlist[ dnsr->d_state ].e_value < dnsr->d_nscount ) {
		/* Check if NS is valid & alive */
		if ( dnsr_send_query( dnsr,
			eventlist[ dnsr->d_state ].e_value ) != 0 ) {
		    return( NULL );
		}
		/* Set query time */
		if ( gettimeofday( &dnsr->d_querytime, NULL ) < 0 ) {
		    DEBUG( perror( "gettimeofday" ));
		    dnsr->d_errno = DNSR_ERROR_SYSTEM;
		    return( NULL );
		}
	    }

	    dnsr->d_state++;
	    DEBUG( fprintf( stderr, "advancing state\n" ));
	    break;

	case DNSR_STATE_DONE: 
	    DEBUG( fprintf( stderr, "STATE_DONE\n" ));
	    goto done;

	default:
	    DEBUG( fprintf( stderr, "Unknown state\n" ));
	    dnsr->d_errno = DNSR_ERROR_STATE;
	    return( NULL );
	}

	/* Check and update timeout */
	if ( timeout != NULL ) {
	    if ( gettimeofday( &cur, NULL ) < 0 ) {
		dnsr->d_errno = DNSR_ERROR_SYSTEM;
		return( NULL );
	    }
	    if ( tv_sub( &end, &cur, timeout ) < 0 ) {
		DEBUG( fprintf( stderr, "dnsr_result: timed out\n" ));
		goto done;
	    }
	}
    }

done:
    if ( resp_errno != DNSR_ERROR_NONE ) {
	dnsr->d_errno = resp_errno;
    } else {
	dnsr->d_errno = DNSR_ERROR_TIMEOUT;
    }
    return( NULL );
}

    void
dnsr_free_result( struct dnsr_result *result )
{
    int 	i;

    if ( result == NULL ) {
	return;
    }

    if ( result->r_ancount > 0 ) {
	for ( i = 0; i < result->r_ancount; i++ ) {
            dnsr_free_ip_info( result->r_answer[ i ].rr_ip );
            if ( result->r_answer[ i ].rr_type == DNSR_TYPE_TXT ) {
                dnsr_free_dnsr_string( result->r_answer[ i ].rr_txt.txt_data );
            }
	}
	free( result->r_answer );
    }

    if ( result->r_nscount > 0 ) {
	for ( i = 0; i < result->r_nscount; i++ ) {
	    dnsr_free_ip_info( result->r_ns[ i ].rr_ip );
	}
	free( result->r_ns );
    }

    if ( result->r_arcount > 0 ) {
	for ( i = 0; i < result->r_arcount; i++ ) {
	    dnsr_free_ip_info( result->r_additional[ i ].rr_ip );
	}
	free( result->r_additional );
    }

    free( result );
}

    void
dnsr_free_ip_info( struct ip_info *i )
{
    struct ip_info      *next;

    while ( i != NULL ) {
        next = i->ip_next;
        free( i );
        i = next;
    }
}

    void
dnsr_free_dnsr_string( struct dnsr_string *t )
{
    struct dnsr_string   *next;

    while ( t != NULL ) {
        next = t->s_next;
        free( t );
        t = next;
    }
}

    int
dnsr_result_expired( DNSR *dnsr, struct dnsr_result *result )
{
    int			i;
    struct timeval	tv_current, tv_expire;

    if ( gettimeofday( &tv_current, NULL ) != 0 ) {
	return( -1 );
    }

    tv_expire.tv_usec = 0;

    for ( i = 0; i < result->r_ancount; i++ ) {
	tv_expire.tv_sec = result->r_answer[ i ].rr_ttl +
	    dnsr->d_querytime.tv_sec;

	if ( tv_gt( &tv_current, &tv_expire )) {
	    return( 1 );
	}
    }

    return( 0 );
}
