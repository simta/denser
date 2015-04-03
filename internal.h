#ifdef __APPLE__
#define socklen_t int
#endif

/* OpCode ( RFC 6895 2.2 ) */
#define DNSR_OP_QUERY	0	/* Standard query */
#define DNSR_OP_IQUERY	1	/* Inverse query (OBSOLETE) */
#define DNSR_OP_STATUS	2	/* Server status request */
#define DNSR_OP_NOTIFY  4       /* Notification of zone change */
#define DNSR_OP_UPDATE  5       /* Dynamic DNS update */

/* RCODE ( RFC 6895 2.3 ) */
#define DNSR_RC_OK		0	/* No Error */
#define DNSR_RC_FORMERR	        1	/* Format Error */
#define DNSR_RC_SERVFAIL	2	/* Server Failure */
#define DNSR_RC_NXDOMAIN	3	/* Non-Existent Domain */
#define DNSR_RC_NOTIMP		4	/* Not Implemented */
#define DNSR_RC_REFUSED		5	/* Query Refused */
#define DNSR_RC_YXDOMAIN        6       /* Name Exists when it should not */
#define DNSR_RC_YXRRSET         7       /* RR Set Exists when it should not */
#define DNSR_RC_NXRRSET         8       /* RR Set that should exist does not */
#define DNSR_RC_NOTAUTH         9       /* Not Authoritative / Not Authorized */
#define DNSR_RC_NOTZONE         10      /* Name not contained in zone */
#define DNSR_RC_BADVERS         16      /* Bad OPT version */
#define DNSR_RC_BADSIG          16      /* duplicate assignment in RFC 2845 */
#define DNSR_RC_BADKEY          17      /* Key not recognized */
#define DNSR_RC_BADTIME         18      /* Signature out of time window */
#define DNSR_RC_BADMODE         19      /* Bad TKEY Mode */
#define DNSR_RC_BADNAME         20      /* Duplicate key name */
#define DNSR_RC_BADALG          21      /* Algorithm not supported */
#define DNSR_RC_BADTRUNC        22      /* Bad Truncation */

#define DNSR_EDNS_UNKNOWN       -1
#define DNSR_EDNS_BAD           -2
#define DNSR_EDNS_VERSION       0

#define DNSR_EDNS_OPT_NSID      3   /* RFC 5001 DNS Name Server Identifier */
#define DNSR_EDNS_OPT_DAU       5   /* RFC 6975 DNSSEC Algorithm Understood */
#define DNSR_EDNS_OPT_DHU       6   /* RFC 6975 DS Hash Understood */
#define DNSR_EDNS_OPT_N3U       7   /* RFC 6975 NSEC3 Hash Understood */
#define DNSR_EDNS_OPT_ECS       8   /* draft-vandergaast-edns-client-subnet */
#define DNSR_EDNS_OPT_EXPIRE    9   /* RFC 7314 EXPIRE */

#define DNSR_DEFAULT_PORT	"53"

/* DNSR bit masks */
#define DNSR_RESPONSE			0x8000
#define DNSR_RECURSION_DESIRED		0x0100
#define DNSR_TRUNCATION			0x0200
#define DNSR_RECURSION_AVAILABLE	0x0080
#define DNSR_RCODE			0x000f
#define DNSR_AUTHORITATIVE_ANSWER	0x0400
#define DNSR_OPCODE			0x7800
#define DNSR_Z				0x0070
#define DNSR_OFFSET			0xc000
#define DNSR_EXTENDED_LABEL             0x4000

#ifdef sun
#define MIN(a,b)        ((a)<(b)?(a):(b))
#define MAX(a,b)        ((a)>(b)?(a):(b))
#endif /* sun */

#ifdef EBUG
#define DEBUG( x )      x
#else
#define DEBUG( x )
#endif

struct dnsr_header {  
    uint16_t   h_id;  
    uint16_t   h_flags;
    uint16_t   h_qdcount;
    uint16_t   h_ancount;
    uint16_t   h_nscount;
    uint16_t   h_arcount;
};

struct dnsr_result *dnsr_create_result( DNSR *, char *, int );
int dnsr_display_header( struct dnsr_header *h );
void dnsr_free_ip_info( struct ip_info * );
void dnsr_free_txt_string( struct txt_string * );
int dnsr_labels_to_name( DNSR *, char *, char **, unsigned int, char *, char **, char * );
int dnsr_labels_to_string( DNSR *, char **, char *, char * );
int dnsr_match_additional( DNSR *, struct dnsr_result * );
int dnsr_match_ip( DNSR *, struct dnsr_rr *, struct dnsr_rr * );
int dnsr_parse_rr( DNSR *, struct dnsr_rr *, struct dnsr_result *, char *, char **, int );
char * dnsr_send_query_tcp( DNSR *, int, int * );
int dnsr_validate_resp( DNSR *, char *, struct sockaddr * );
int dnsr_validate_result( DNSR *, struct dnsr_result * );
