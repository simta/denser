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

#include "bprint.h"
#include "denser.h"
#include "event.h"
#include "internal.h"
#include "timeval.h"

static int dn_to_labels(DNSR *dnsr, char *dn, char *labels);

struct question {
    uint16_t q_type;
    uint16_t q_class;
};

struct lookup {
    int l_key;
    int l_value;
};

struct lookup lookup_type[] = {
        {0, -1}, {DNSR_TYPE_A, DNSR_TYPE_A}, /* Host address */
        {DNSR_TYPE_NS, DNSR_TYPE_NS},        /* Authoritative name server */
        {DNSR_TYPE_MD, DNSR_TYPE_MD},        /* Mail destination */
        {DNSR_TYPE_MF, DNSR_TYPE_MF},        /* Mail forwarder */
        {DNSR_TYPE_CNAME, DNSR_TYPE_CNAME},  /* Canonical name for an alias */
        {DNSR_TYPE_SOA, DNSR_TYPE_SOA},      /* Start of a zone of authority */
        {DNSR_TYPE_MB, DNSR_TYPE_MB},        /* Mailbox domain */
        {DNSR_TYPE_MG, DNSR_TYPE_MG},        /* Mail group member */
        {DNSR_TYPE_MR, DNSR_TYPE_MR},        /* Mail rename domain name */
        {DNSR_TYPE_NULL, DNSR_TYPE_NULL},    /* Null RR */
        {DNSR_TYPE_WKS, DNSR_TYPE_WKS},     /* Well known service description */
        {DNSR_TYPE_PTR, DNSR_TYPE_PTR},     /* Domain name pointer */
        {DNSR_TYPE_HINFO, DNSR_TYPE_HINFO}, /* Host information */
        {DNSR_TYPE_MINFO, DNSR_TYPE_MINFO}, /* Mailbox or mail list info */
        {DNSR_TYPE_MX, DNSR_TYPE_MX},       /* Mail exchange */
        {DNSR_TYPE_TXT, DNSR_TYPE_TXT},     /* Text string */
        {17, -1}, {18, -1}, {19, -1}, {20, -1}, {21, -1}, {22, -1}, {23, -1},
        {24, -1}, {25, -1}, {26, -1}, {27, -1},
        {DNSR_TYPE_AAAA, DNSR_TYPE_AAAA}, /* IPv6 record, RFC 3596 */
        {29, -1}, {30, -1}, {31, -1}, {32, -1},
        {DNSR_TYPE_SRV, DNSR_TYPE_SRV}, /* Service Record RFC 2728 */
        {34, -1}, {35, -1}, {36, -1}, {37, -1}, {38, -1}, {39, -1}, {40, -1},
        {DNSR_TYPE_OPT, DNSR_TYPE_OPT}, /* EDNS OPT, RFC 6891 */
        {42, -1}, {43, -1}, {44, -1}, {45, -1}, {46, -1}, {47, -1}, {48, -1},
        {49, -1}, {50, -1}, {51, -1}, {52, -1}, {53, -1}, {54, -1}, {55, -1},
        {56, -1}, {57, -1}, {58, -1}, {59, -1}, {60, -1}, {61, -1}, {62, -1},
        {63, -1}, {64, -1}, {65, -1}, {66, -1}, {67, -1}, {68, -1}, {69, -1},
        {70, -1}, {71, -1}, {72, -1}, {73, -1}, {74, -1}, {75, -1}, {76, -1},
        {77, -1}, {78, -1}, {79, -1}, {80, -1}, {81, -1}, {82, -1}, {83, -1},
        {84, -1}, {85, -1}, {86, -1}, {87, -1}, {88, -1}, {89, -1}, {90, -1},
        {91, -1}, {92, -1}, {93, -1}, {94, -1}, {95, -1}, {96, -1}, {97, -1},
        {98, -1}, {99, -1}, {100, -1}, {101, -1}, {102, -1}, {103, -1},
        {104, -1}, {105, -1}, {106, -1}, {107, -1}, {108, -1}, {109, -1},
        {110, -1}, {111, -1}, {112, -1}, {113, -1}, {114, -1}, {115, -1},
        {116, -1}, {117, -1}, {118, -1}, {119, -1}, {120, -1}, {121, -1},
        {122, -1}, {123, -1}, {124, -1}, {125, -1}, {126, -1}, {127, -1},
        {128, -1}, {129, -1}, {130, -1}, {131, -1}, {132, -1}, {133, -1},
        {134, -1}, {135, -1}, {136, -1}, {137, -1}, {138, -1}, {139, -1},
        {140, -1}, {141, -1}, {142, -1}, {143, -1}, {144, -1}, {145, -1},
        {146, -1}, {147, -1}, {148, -1}, {149, -1}, {150, -1}, {151, -1},
        {152, -1}, {153, -1}, {154, -1}, {155, -1}, {156, -1}, {157, -1},
        {158, -1}, {159, -1}, {160, -1}, {161, -1}, {162, -1}, {163, -1},
        {164, -1}, {165, -1}, {166, -1}, {167, -1}, {168, -1}, {169, -1},
        {170, -1}, {171, -1}, {172, -1}, {173, -1}, {174, -1}, {175, -1},
        {176, -1}, {177, -1}, {178, -1}, {179, -1}, {180, -1}, {181, -1},
        {182, -1}, {183, -1}, {184, -1}, {185, -1}, {186, -1}, {187, -1},
        {188, -1}, {189, -1}, {190, -1}, {191, -1}, {192, -1}, {193, -1},
        {194, -1}, {195, -1}, {196, -1}, {197, -1}, {198, -1}, {199, -1},
        {200, -1}, {201, -1}, {202, -1}, {203, -1}, {204, -1}, {205, -1},
        {206, -1}, {207, -1}, {208, -1}, {209, -1}, {210, -1}, {211, -1},
        {212, -1}, {213, -1}, {214, -1}, {215, -1}, {216, -1}, {217, -1},
        {218, -1}, {219, -1}, {220, -1}, {221, -1}, {222, -1}, {223, -1},
        {224, -1}, {225, -1}, {226, -1}, {227, -1}, {228, -1}, {229, -1},
        {230, -1}, {231, -1}, {232, -1}, {233, -1}, {234, -1}, {235, -1},
        {236, -1}, {237, -1}, {238, -1}, {239, -1}, {240, -1}, {241, -1},
        {242, -1}, {243, -1}, {244, -1}, {245, -1}, {246, -1}, {247, -1},
        {248, -1}, {249, -1}, {250, -1}, {251, -1}, {252, -1}, {253, -1},
        {254, -1}, {DNSR_TYPE_ALL, DNSR_TYPE_ALL} /* all records */
};

struct lookup lookup_class[] = {
        {0, -1}, {DNSR_CLASS_IN, 1}, /* Internet */
        {2, -1},                     /* Available */
        {DNSR_CLASS_CH, 3},          /* CHAOS */
        {DNSR_CLASS_HS, 4}           /* HESIOD */
};

char *
dnsr_ntoptr(DNSR *dnsr, int af, const void *src, const char *suffix) {
    char *   res;
    char *   p;
    int      i, reverselen;
    uint8_t *iparr;

    iparr = (uint8_t *)src;

    if (af == AF_INET) {
        suffix = suffix ? suffix : "in-addr.arpa";
        reverselen = INET_ADDRSTRLEN + strlen(suffix) + 2;
    } else if (af == AF_INET6) {
        /* RFC 3596 2.5 IP6.ARPA Domain
         * An IPv6 address is represented as a name in the IP6.ARPA domain by a
         * sequence of nibbles separated by dots with the suffix ".IP6.ARPA".
         * The sequence of nibbles is encoded in reverse order, i.e., the
         * low-order nibble is encoded first, followed by the next low-order
         * nibble and so on.  Each nibble is represented by a hexadecimal digit.
         */
        suffix = suffix ? suffix : "ip6.arpa";
        /* RFC 2373 2.0 IPv6 ADDRESSING
         * IPv6 addresses are 128-bit identifiers
         *
         * 128 bits = 32 nibbles + 32 dots.
         */
        reverselen = 64 + strlen(suffix) + 2;
    } else {
        dnsr->d_errno = DNSR_ERROR_UNKNOWN;
        return (NULL);
    }

    if ((res = (char *)malloc(reverselen)) == NULL) {
        DEBUG(perror("malloc"));
        dnsr->d_errno = DNSR_ERROR_SYSTEM;
        return (NULL);
    }
    memset(res, 0, reverselen);

    if (af == AF_INET) {
        sprintf(res, "%u.%u.%u.%u.%s", iparr[ 3 ], iparr[ 2 ], iparr[ 1 ],
                iparr[ 0 ], suffix);
    } else if (af == AF_INET6) {
        p = res;
        for (i = 15; i >= 0; i--) {
            sprintf(p, "%x.%x.", iparr[ i ] & 0x0f, (iparr[ i ] >> 4) & 0x0f);
            p += 4;
        }
        sprintf(p, "%s", suffix);
    }

    return (res);
}

char *
dnsr_reverse_ip(DNSR *dnsr, const char *ip, const char *suffix) {
    int            af = AF_INET;
    struct in_addr ipaddr;

    if (strchr(ip, ':') != NULL) {
        af = AF_INET6;
    }

    if (inet_pton(af, ip, &ipaddr) <= 0) {
        DEBUG(perror("inet_pton"));
        dnsr->d_errno = DNSR_ERROR_SYSTEM;
        return (NULL);
    }

    return (dnsr_ntoptr(dnsr, af, &ipaddr.s_addr, suffix));
}

static int
dn_to_labels(DNSR *dnsr, char *dn, char *labels) {
    char *label = NULL, *p = NULL;
    int   i = 0, len = 0, done = 0;

    dnsr->d_errno = 0;

    /* Check for and remove trailing '.' */
    len = strlen(dn);
    if (len > DNSR_MAX_HOSTNAME) {
        DEBUG(fprintf(stderr, "dn_to_labels: dn too long\n"));
        dnsr->d_errno = DNSR_ERROR_SIZELIMIT_EXCEEDED;
        return (-1);
    }
    /* XXX - check length of domain name */
    if (dn[ len - 1 ] == '.') {
        dn[ len - 1 ] = (char)'\0';
        len--;
    }
    if (len == 0) {
        labels[ i++ ] = 0;
        return (i);
    }

    label = dn;

    for (;;) {
        /* Find label */
        if ((p = strchr(label, '.')) == NULL) {
            done = 1;
            len = strlen(label);
        } else {
            len = p - label;
        }

        if (len == 0) {
            DEBUG(fprintf(stderr, "dn_to_labels: %s: empty label\n", dn));
            dnsr->d_errno = DNSR_ERROR_FORMAT;
            return (-1);
        } else if (len > 63) {
            DEBUG(fprintf(stderr, "dn_to_labels: %s: label too long\n", dn));
            dnsr->d_errno = DNSR_ERROR_SIZELIMIT_EXCEEDED;
            return (-1);
        }
        labels[ i++ ] = len;
        memcpy(&labels[ i ], label, (size_t)len);
        i += len;
        if (done) {
            labels[ i++ ] = 0;
            break;
        }

        label = p + 1;
    }

    if (i > 255) {
        fprintf(stderr, "%s: dn too long\n", dn);
        return (-1);
    }
    return (i);
}

/*
 * This function sends a query to a nameserver.
 *
 * Arguments:
 *      A dnsr that has been initalized with dnsr_new and a query.
 *
 *      An int indexing the nameserver listed in dnsr where packet is
 *      to be sent.
 *
 * Return:
 *      < 1     System error
 *      0       OK
 *      >1      Temporary error
 */

int
dnsr_send_query(DNSR *dnsr, int ns) {
    struct dnsr_header *h;
    char *              query;
    char                buf[ DNSR_MAX_UDP ];
    size_t              querylen;
    ssize_t             rc;

    if (dnsr->d_nsinfo[ ns ].ns_edns == DNSR_EDNS_BAD) {
        /* EDNS is bad, strip it off */
        DEBUG(fprintf(stderr, "stripping EDNS\n"));
        querylen = dnsr->d_questionlen;
        memcpy(buf, dnsr->d_query, querylen);
        query = buf;
        h = (struct dnsr_header *)query;
        h->h_arcount = htons(ntohs(h->h_arcount) - 1);
    } else {
        query = dnsr->d_query;
        querylen = dnsr->d_querylen;
    }

    if (querylen > dnsr->d_nsinfo[ ns ].ns_udp) {
        DEBUG(fprintf(stderr, "query is too large for UDP on ns %d", ns));
        dnsr->d_errno = DNSR_ERROR_SIZELIMIT_EXCEEDED;
        return (-1);
    }

    /* Set unique ID for query */
    h = (struct dnsr_header *)query;
    h->h_id = htons(dnsr->d_id ^ dnsr->d_nsinfo[ ns ].ns_id);

    /* Send query */
    if (dnsr->d_nsinfo[ ns ].ns_sa.ss_family == AF_INET) {
        rc = sendto(dnsr->d_fd, query, querylen, 0,
                (struct sockaddr *)&dnsr->d_nsinfo[ ns ].ns_sa,
                sizeof(struct sockaddr_in));
    } else {
        rc = sendto(dnsr->d_fd6, query, querylen, 0,
                (struct sockaddr *)&dnsr->d_nsinfo[ ns ].ns_sa,
                sizeof(struct sockaddr_in6));
    }
    if (rc != querylen) {
        DEBUG(perror("sendto"));
        dnsr->d_errno = DNSR_ERROR_SYSTEM;
        return (-1);
    }

    DEBUG(dnsr_display_header((struct dnsr_header *)query));

    if (gettimeofday(&dnsr->d_querytime, NULL) < 0) {
        DEBUG(perror("gettimeofday"));
        dnsr->d_errno = DNSR_ERROR_SYSTEM;
        return (-1);
    }
    dnsr->d_querysent = 1;
    dnsr->d_nsinfo[ ns ].ns_asked = 1;

    return 0;
}


/* rfc 1035 4.2.2
 * Messages sent over TCP connections use server port 53 (decimal).  The
 * message is prefixed with a two byte length field which gives the message
 * length, excluding the two byte length field.  This length field allows
 * the low-level processing to assemble a complete message before beginning
 * to parse it.
 */

char *
dnsr_send_query_tcp(DNSR *dnsr, int ns, int *resplen) {

    char *              resp_tcp = NULL;
    int                 fd;
    ssize_t             size = 0, rc;
    struct dnsr_header *h;
    char                buf[ DNSR_MAX_UDP ];
    char *              query;
    uint16_t            querylen, len;

    if ((fd = socket(dnsr->d_nsinfo[ ns ].ns_sa.ss_family, SOCK_STREAM, 0)) <
            0) {
        DEBUG(perror("dnsr_send_query_tcp: socket"));
        dnsr->d_errno = DNSR_ERROR_SYSTEM;
        return (NULL);
    }

    if (connect(fd, (struct sockaddr *)&dnsr->d_nsinfo[ ns ].ns_sa,
                sizeof(struct sockaddr_storage)) != 0) {
        DEBUG(perror("dnsr_send_query_tcp: connect"));
        dnsr->d_errno = DNSR_ERROR_SYSTEM;
        goto error;
    }

    if (dnsr->d_nsinfo[ ns ].ns_edns == DNSR_EDNS_BAD) {
        /* EDNS is bad, strip it off */
        DEBUG(fprintf(stderr, "stripping EDNS\n"));
        querylen = dnsr->d_questionlen;
        memcpy(buf, dnsr->d_query, DNSR_MAX_UDP);
        query = buf;
        h = (struct dnsr_header *)query;
        h->h_arcount = htons(ntohs(h->h_arcount) - 1);
    } else {
        querylen = dnsr->d_querylen;
        query = dnsr->d_query;
    }

    len = htons(querylen);
    if (write(fd, &len, sizeof(len)) != sizeof(len)) {
        DEBUG(perror("dnsr_send_query_tcp: send"));
        dnsr->d_errno = DNSR_ERROR_SYSTEM;
        goto error;
    }
    DEBUG(fprintf(stderr, "wrote len %d\n", len));

    if (write(fd, query, (size_t)querylen) != querylen) {
        DEBUG(perror("dnsr_send_query_tcp: send"));
        dnsr->d_errno = DNSR_ERROR_SYSTEM;
        goto error;
    }
    DEBUG(fprintf(stderr, "wrote query\n"));
    DEBUG(bprint(query, (size_t)querylen));

    if ((rc = read(fd, &len, sizeof(len))) != sizeof(len)) {
        DEBUG(perror("dnsr_send_query_tcp: read"));
        dnsr->d_errno = DNSR_ERROR_SYSTEM;
        goto error;
    }
    len = ntohs(len);
    *resplen = len;
    DEBUG(fprintf(stderr, "response len: %d\n", len));

    if ((resp_tcp = malloc(len)) == NULL) {
        DEBUG(perror("malloc"));
        dnsr->d_errno = DNSR_ERROR_SYSTEM;
        goto error;
    }

    while (size < len) {
        if ((rc = read(fd, &resp_tcp[ size ], len)) <= 0) {
            if (rc == 0) {
                DEBUG(fprintf(stderr, "dnsr_send_query_tcp: read: closed"));
                dnsr->d_errno = DNSR_ERROR_CONNECTION_CLOSED;
            } else {
                DEBUG(perror("dnsr_send_query_tcp: read"));
                dnsr->d_errno = DNSR_ERROR_SYSTEM;
            }
            goto error;
        }
        size += rc;
    }

    DEBUG(fprintf(stderr, "response\n"));
    DEBUG(bprint(resp_tcp, len));

    close(fd);
    return (resp_tcp);

error:
    free(resp_tcp);
    close(fd);
    return (NULL);
}

int
dnsr_query(DNSR *dnsr, uint16_t qtype, uint16_t qclass, const char *dn) {
    int                 i, len;
    struct dnsr_header *h;
    struct question     q;

    if (!dnsr) {
        return (-1);
    }

    /* If dnsr handle has not been configured, do so now */
    if (dnsr->d_nscount == 0) {
        if (dnsr_nameserver(dnsr, NULL) != 0) {
            return (-1);
        }
    }

    /* Check for valid type */
    if ((qtype <= 0) || (qtype > DNSR_MAX_TYPE) ||
            (lookup_type[ qtype ].l_value != qtype)) {
        dnsr->d_errno = DNSR_ERROR_TYPE;
        return (-1);
    }

    /* Check for valid type */
    if ((qclass <= 0) || (qclass > DNSR_MAX_CLASS) ||
            (lookup_class[ qclass ].l_value != qclass)) {
        dnsr->d_errno = DNSR_ERROR_CLASS;
        return (-1);
    }

    if ((len = strlen(dn)) > DNSR_MAX_NAME) {
        DEBUG(fprintf(stderr, "dnsr_query: dn too long\n"));
        dnsr->d_errno = DNSR_ERROR_SIZELIMIT_EXCEEDED;
        return (-1);
    }
    strcpy(dnsr->d_dn, dn);
    if (dnsr->d_dn[ len - 1 ] == '.') {
        dnsr->d_dn[ len ] = '\0';
        len--;
    }

    dnsr->d_id = rand() & 0xffff;
    dnsr->d_querylen = 0;
    dnsr->d_querysent = 0;
    dnsr->d_state = 0;
    memset(&dnsr->d_querytime, 0, sizeof(struct timeval));

    /* Create header */
    h = (struct dnsr_header *)dnsr->d_query;
    memset(h, 0, DNSR_MAX_UDP);
    h->h_flags = htons(dnsr->d_flags);
    h->h_qdcount = htons(1);
    h->h_arcount = htons(1);

    dnsr->d_querylen += sizeof(struct dnsr_header);

    /* Create question */
    /* Since we have already checked the length of dn, we know
     * it's corresponding query can't be too big, so we don't have
     * to check the size.
     */
    if ((i = dn_to_labels(
                 dnsr, dnsr->d_dn, &dnsr->d_query[ dnsr->d_querylen ])) < 0) {
        return (-1);
    }
    dnsr->d_querylen += i;
    q.q_type = htons(qtype);
    q.q_class = htons(qclass);
    memcpy(&dnsr->d_query[ dnsr->d_querylen ], &q, sizeof(q));
    dnsr->d_querylen += sizeof(q);
    dnsr->d_questionlen = dnsr->d_querylen;

    /* RFC 6891 6.1.2 Wire Format
     * The fixed part of an OPT RR is structured as follows:
     *      Field Name   Field Type     Description
     *      ------------------------------------------------------
     *      NAME         domain name    MUST be 0 (root domain)
     *      TYPE         u_int16_t      OPT (41)
     *      CLASS        u_int16_t      requestor's UDP payload size
     *      TTL          u_int32_t      extended RCODE and flags
     *      RDLEN        u_int16_t      length of all RDATA
     *      RDATA        octet stream   {attribute,value} pairs
     */

    /* FIXME: this whole thing is ugly. */
    dnsr->d_query[ dnsr->d_querylen++ ] = 0;
    uint16_t temp;
    uint32_t tempflags;
    temp = htons(DNSR_TYPE_OPT);
    memcpy(&dnsr->d_query[ dnsr->d_querylen ], &temp, sizeof(uint16_t));
    dnsr->d_querylen += sizeof(uint16_t);
    temp = htons(DNSR_MAX_UDP);
    memcpy(&dnsr->d_query[ dnsr->d_querylen ], &temp, sizeof(uint16_t));
    dnsr->d_querylen += sizeof(uint16_t);
    tempflags = 0;
    memcpy(&dnsr->d_query[ dnsr->d_querylen ], &tempflags, sizeof(uint32_t));
    dnsr->d_querylen += sizeof(uint32_t);
    temp = htons(sizeof(uint16_t) * 2);
    memcpy(&dnsr->d_query[ dnsr->d_querylen ], &temp, sizeof(uint16_t));
    dnsr->d_querylen += sizeof(uint16_t);
    temp = htons(DNSR_EDNS_OPT_NSID);
    memcpy(&dnsr->d_query[ dnsr->d_querylen ], &temp, sizeof(uint16_t));
    dnsr->d_querylen += sizeof(uint16_t);
    temp = htons(0);
    memcpy(&dnsr->d_query[ dnsr->d_querylen ], &temp, sizeof(uint16_t));
    dnsr->d_querylen += sizeof(uint16_t);

    DEBUG(fprintf(stderr, "nscount: %d\n", dnsr->d_nscount));

    /* Send query to NS 0 */
    DEBUG(fprintf(stderr, "sending query to: 0\n"));
    if (dnsr_send_query(dnsr, 0) != 0) {
        if (dnsr->d_errno == DNSR_ERROR_SYSTEM) {
            return (-1);
        }
    }

    dnsr->d_state = 0;

    return 0;
}
