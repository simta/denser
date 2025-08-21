/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "argcargv.h"
#include "bprint.h"
#include "denser.h"
#include "internal.h"
#include "timeval.h"

static int dnsr_parse_resolv(DNSR *dnsr);
static int dnsr_nameserver_add(
        DNSR *dnsr, const char *nameserver, const char *port, int index);
static void dnsr_nameserver_reset(DNSR *dnsr);

static char *dnsr_resolvconf_path = DNSR_RESOLV_CONF_PATH;

/*
 * TODO:  accept an auth section to configure name servers
 * Limit of 4 name servers
 * expects a UNIX resolv.conf ( XXX - posix? )
 */

int
dnsr_nameserver_port(DNSR *dnsr, const char *server, const char *port) {
    int rc;

    /* Clear any existing nameservers */
    dnsr_nameserver_reset(dnsr);

    if (server == NULL) {
        if ((rc = dnsr_parse_resolv(dnsr)) != 0) {
            return (rc);
        }
    } else {
        if ((rc = dnsr_nameserver_add(dnsr, server, port, 0)) != 0) {
            return (rc);
        }
        dnsr->d_nscount++;
    }

    /* Set default NS */
    if (dnsr->d_nscount == 0) {
        if ((rc = dnsr_nameserver_add(
                     dnsr, "INADDR_LOOPBACK", DNSR_DEFAULT_PORT, 0)) != 0) {
            return (rc);
        }
        dnsr->d_nscount++;
    }

    return 0;
}

int
dnsr_nameserver(DNSR *dnsr, const char *server) {
    return (dnsr_nameserver_port(dnsr, server, DNSR_DEFAULT_PORT));
}

int
dnsr_config(DNSR *dnsr, int flag, int toggle) {
    switch (flag) {
    case DNSR_FLAG_RECURSION:
        switch (toggle) {
        case DNSR_FLAG_ON:
            dnsr->d_flags = dnsr->d_flags | DNSR_RECURSION_DESIRED;
            break;

        case DNSR_FLAG_OFF:
            dnsr->d_flags = dnsr->d_flags & ~DNSR_RECURSION_DESIRED;
            break;

        default:
            DEBUG(fprintf(stderr, "dnsr_config: %d: unknown toggle\n", toggle));
            dnsr->d_errno = DNSR_ERROR_TOGGLE;
            return (-1);
        }
        break;

    default:
        DEBUG(fprintf(stderr, "dnsr_config: %d: unknown flag\n", flag));
        dnsr->d_errno = DNSR_ERROR_FLAG;
        return (-1);
    }

    return 0;
}

/* An empty file, or one without any valid nameservers defaults to local host
 * Can only add one server by hand, that will use default port
 */

static int
dnsr_parse_resolv(DNSR *dnsr) {
    int    len, rc;
    uint   linenum = 0;
    char   buf[ DNSR_MAX_LINE ];
    char **argv;
    int    argc;
    FILE  *f;

    if ((f = fopen(dnsr_resolvconf_path, "r")) == NULL) {
        DEBUG(perror(dnsr_resolvconf_path));
        /* Not an error if DNSR_RESOLVECONF_PATH missing - not required */
        if (errno == ENOENT) {
            errno = 0;
            return 0;
        } else {
            dnsr->d_errno = DNSR_ERROR_SYSTEM;
            return (-1);
        }
    }

    while (fgets((char *)&buf, DNSR_MAX_LINE, f) != 0) {
        linenum++;

        len = strlen(buf);
        if (buf[ len - 1 ] != '\n') {
            DEBUG(fprintf(stderr, "parse_resolve: %s: %d: line too long\n",
                    dnsr_resolvconf_path, linenum));
            continue;
        }

        if ((argc = acav_parse(NULL, buf, &argv)) < 0) {
            DEBUG(perror("parse_resolve: acav_parse"));
            dnsr->d_errno = DNSR_ERROR_SYSTEM;
            return (-1);
        }

        if ((argc == 0) || (*argv[ 0 ] == '#')) {
            continue;
        }

        if (strcmp(argv[ 0 ], "nameserver") == 0) {
            if (dnsr->d_nscount < DNSR_MAX_NS) {
                if ((rc = dnsr_nameserver_add(dnsr, argv[ 1 ],
                             DNSR_DEFAULT_PORT, dnsr->d_nscount)) > 0) {
                    return (rc);
                } else if (rc == 0) {
                    dnsr->d_nscount++;
                }
            } else {
                DEBUG(fprintf(stderr,
                        "parse_resolve: nameserver %s not added: too many\n",
                        argv[ 1 ]));
            }
        }
    }
    if (ferror(f)) {
        DEBUG(perror("fgets"));
        dnsr->d_errno = DNSR_ERROR_SYSTEM;
        return (-1);
    }
    if (fclose(f) != 0) {
        DEBUG(perror("fclose"));
        dnsr->d_errno = DNSR_ERROR_SYSTEM;
        return (-1);
    }

    return 0;
}

static int
dnsr_nameserver_add(
        DNSR *dnsr, const char *nameserver, const char *port, int index) {
    struct addrinfo  hints;
    struct addrinfo *result;
    int              s;

    if ((index < 0) || (index > DNSR_MAX_NS)) {
        DEBUG(fprintf(stderr, "%d: index out of range\n", index));
        dnsr->d_errno = DNSR_ERROR_CONFIG;
        return 1;
    }
    DEBUG(fprintf(stderr, "name server %d: %s\n", index, nameserver));

    dnsr->d_nsinfo[ index ].ns_id = rand() & 0xffff;
    dnsr->d_nsinfo[ index ].ns_udp = DNSR_MAX_UDP_BASIC;
    dnsr->d_nsinfo[ index ].ns_edns = DNSR_EDNS_UNKNOWN;

    memset(&hints, 0, sizeof(struct addrinfo));

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

    if ((s = getaddrinfo(nameserver, port, &hints, &result))) {
        DEBUG(fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s)));
        dnsr->d_errno = DNSR_ERROR_CONFIG;
        return 1;
    }

    /* FIXME: getaddrinfo may have returned multiple results. Do we care? */
    if (result->ai_family == AF_INET) {
        memcpy(&(dnsr->d_nsinfo[ index ].ns_sa), result->ai_addr,
                sizeof(struct sockaddr_in));
    } else if (result->ai_family == AF_INET6) {
        memcpy(&(dnsr->d_nsinfo[ index ].ns_sa), result->ai_addr,
                sizeof(struct sockaddr_in6));
    } else {
        freeaddrinfo(result);
        return (-1);
    }

    freeaddrinfo(result);
    return 0;
}

void
dnsr_nameserver_reset(DNSR *dnsr) {
    int i;

    for (i = 0; i < dnsr->d_nscount; i++) {
        dnsr->d_nsinfo[ i ].ns_id = 0;
    }
    dnsr->d_nscount = 0;
}
