/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include <arpa/inet.h>
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
#include <unistd.h>

#include "bprint.h"
#include "denser.h"
#include "internal.h"

int densetype(char *type);
int print_rr(struct dnsr_rr *rr);

struct densetype {
    const char *dt_name;
    int         dt_value;
} densetypes[] = {
        {"A", DNSR_TYPE_A},
        {"AAAA", DNSR_TYPE_AAAA},
        {"MX", DNSR_TYPE_MX},
        {"SOA", DNSR_TYPE_SOA},
        {"TXT", DNSR_TYPE_TXT},
        {"CNAME", DNSR_TYPE_CNAME},
        {"PTR", DNSR_TYPE_PTR},
        {"SRV", DNSR_TYPE_SRV},
        {"ALL", DNSR_TYPE_ALL},
        {NULL, 0},
};

int
densetype(char *type) {
    struct densetype *dtn;

    for (dtn = densetypes; dtn->dt_name != NULL; dtn++) {
        if (strcasecmp(dtn->dt_name, type) == 0) {
            return (dtn->dt_value);
        }
    }
    return (-1);
}

int
print_rr(struct dnsr_rr *rr) {
    struct ip_info *ip_info;

    if (rr->rr_type != DNSR_TYPE_OPT) {
        printf("%s\t", rr->rr_name);

        printf("%dd %02dh %02dm %02ds", rr->rr_ttl / 86400,
                (rr->rr_ttl % 86400) / 3600, (rr->rr_ttl % 3600) / 60,
                rr->rr_ttl % 60);
    }

    switch (rr->rr_type) {
    case DNSR_TYPE_CNAME:
        printf("\tCNAME");
        printf("\t%s\n", rr->rr_dn.dn_name);
        break;

    case DNSR_TYPE_MB:
        printf("\tMB");
        printf("\t%s\n", rr->rr_dn.dn_name);
        break;

    case DNSR_TYPE_MD:
        printf("\tMD");
        printf("\t%s\n", rr->rr_dn.dn_name);
        break;

    case DNSR_TYPE_MF:
        printf("\tMF");
        printf("\t%s\n", rr->rr_dn.dn_name);
        break;

    case DNSR_TYPE_MG:
        printf("\tMG");
        printf("\t%s\n", rr->rr_dn.dn_name);
        break;

    case DNSR_TYPE_MR:
        printf("\tMR");
        printf("\t%s\n", rr->rr_dn.dn_name);
        break;

    case DNSR_TYPE_NS:
        printf("\tNS");
        printf("\t%s\n", rr->rr_dn.dn_name);
        break;

    case DNSR_TYPE_PTR:
        printf("\tPTR");
        printf("\t%s\n", rr->rr_dn.dn_name);
        break;

    case DNSR_TYPE_HINFO:
        printf("\tHINFO");
        printf("\tCPU: %s\n", rr->rr_hinfo.hi_cpu);
        printf("\tOS: %s\n", rr->rr_hinfo.hi_os);
        break;

    case DNSR_TYPE_MX:
        printf("\tMX");
        printf("\t%d %s\n", rr->rr_mx.mx_preference, rr->rr_mx.mx_exchange);
        break;

    case DNSR_TYPE_NULL:
        printf("\tNULL\n");
        break;

    case DNSR_TYPE_SOA:
        printf("\tSOA");
        printf("\tmname: %s\trname: %s\n\tserial: %d\n\trefresh: %d\n",
                rr->rr_soa.soa_mname, rr->rr_soa.soa_rname,
                rr->rr_soa.soa_serial, rr->rr_soa.soa_refresh);
        printf("\tretry: %d\n\texpire: %d\n\tminimum: %d\n",
                rr->rr_soa.soa_retry, rr->rr_soa.soa_expire,
                rr->rr_soa.soa_minimum);
        break;

    case DNSR_TYPE_TXT: {
        struct dnsr_string *txt;
        txt = rr->rr_txt.txt_data;
        printf("\tTXT");
        while (txt != NULL) {
            printf("\t%s\n", txt->s_string);
            txt = txt->s_next;
        }
        break;
    }

    case DNSR_TYPE_A: {
        char buf[ INET_ADDRSTRLEN ];
        printf("\tA");
        printf("\t%s\n", inet_ntop(AF_INET, &(rr->rr_a), buf, INET_ADDRSTRLEN));
        break;
    }

    case DNSR_TYPE_SRV:
        printf("\tSRV");
        printf("\ttarget: %s\tpriority: %d\tweight: %d\tport: %d\n",
                rr->rr_srv.srv_target, rr->rr_srv.srv_priority,
                rr->rr_srv.srv_weight, rr->rr_srv.srv_port);
        break;

    case DNSR_TYPE_AAAA: {
        char buf[ INET6_ADDRSTRLEN ];
        printf("\tAAAA");
        printf("\t%s\n",
                inet_ntop(AF_INET6, &(rr->rr_aaaa), buf, INET6_ADDRSTRLEN));
        break;
    }

    case DNSR_TYPE_OPT: {
        struct edns_opt *opt;
        printf("EDNS OPT:\tversion %d udp %d\n", rr->rr_opt.opt_version,
                rr->rr_opt.opt_udp);
        for (opt = rr->rr_opt.opt_opt; opt != NULL; opt = opt->opt_next) {
            printf("\t%d\t", opt->opt_code);
            int i;
            for (i = 0; i < opt->opt_len; i++) {
                printf("%x", opt->opt_data[ i ]);
            }
            printf("\t");
            for (i = 0; i < opt->opt_len; i++) {
                printf("%c", opt->opt_data[ i ]);
            }
            printf("\n");
        }
        break;
    }
    default:
        printf("\t%d: unknown type\n", rr->rr_type);
        break;
    }

    if (rr->rr_type != DNSR_TYPE_A) {
        char buf[ INET6_ADDRSTRLEN ];
        for (ip_info = rr->rr_ip; ip_info; ip_info = ip_info->ip_next) {
            printf("\t%s\n",
                    inet_ntop(ip_info->ip_sa.ss_family,
                            ((ip_info->ip_sa.ss_family == AF_INET)
                                            ? (void *)&(
                                                      ((struct sockaddr_in *)&(
                                                               ip_info->ip_sa))
                                                              ->sin_addr)
                                            : (void *)&(
                                                      ((struct sockaddr_in6 *)&(
                                                               ip_info->ip_sa))
                                                              ->sin6_addr)),
                            buf, INET6_ADDRSTRLEN));
        }
    }
    return 0;
}

int
main(int argc, char *argv[]) {
    char                c;
    char *              name, *host = NULL, *type = "A";
    extern int          optind;
    DNSR *              dnsr;
    int                 i, err = 0, typenum, display_all = 0;
    int                 recursion = 1;
    int                 test_cache = 0;
    struct dnsr_result *result;

    while ((c = getopt(argc, argv, "ach:rt:")) != EOF) {
        switch (c) {
        case 'a':
            display_all = 1;
            break;

        case 'c':
            test_cache = 1;

        case 'h':
            host = optarg;
            break;

        case 'r':
            recursion = 0;
            break;

        case 't':
            type = optarg;
            break;

        default:
            err++;
        }
    }

    if (argc - optind != 1) {
        err++;
    }

    if (err) {
        fprintf(stderr, "usage: %s [ -acr ] ", argv[ 0 ]);
        fprintf(stderr, "[ -h server ] [ -t type ] ");
        fprintf(stderr, "query\n");
        exit(1);
    }

    name = argv[ argc - 1 ];

    if ((typenum = densetype(type)) < 0) {
        fprintf(stderr, "%s: invalid type\n", argv[ 1 ]);
        exit(1);
    }

    if ((dnsr = dnsr_new()) == NULL) {
        dnsr_perror(dnsr, "dnsr_new");
        exit(1);
    }

    if (host != NULL) {
        if (dnsr_nameserver(dnsr, host) != 0) {
            dnsr_perror(dnsr, "dnsr_nameserver");
            exit(1);
        }
    }
    if (!recursion) {
        if (dnsr_config(dnsr, DNSR_FLAG_RECURSION, DNSR_FLAG_OFF) != 0) {
            dnsr_perror(dnsr, "dnsr_config");
            exit(1);
        }
        printf("No recursion\n");
    }

    if (typenum == DNSR_TYPE_PTR) {
        if ((name = dnsr_reverse_ip(dnsr, name, NULL)) == NULL) {
            dnsr_perror(dnsr, "dnsr_reverse_ip");
            exit(1);
        }
    }

    printf("searching for %s record on %s\n", type, name);
    if ((dnsr_query(dnsr, typenum, DNSR_CLASS_IN, name)) != 0) {
        dnsr_perror(dnsr, "query");
        exit(1);
    }
    if (typenum == DNSR_TYPE_PTR) {
        free(name);
    }
    if ((result = dnsr_result(dnsr, NULL)) == NULL) {
        dnsr_perror(dnsr, "dnsr_result");
        exit(1);
    }

    printf("# Answer Section:\n");
    for (i = 0; i < result->r_ancount; i++) {
        print_rr(&result->r_answer[ i ]);
    }

    if (display_all) {
        printf("\n# Authority Section:\n");
        for (i = 0; i < result->r_nscount; i++) {
            print_rr(&result->r_ns[ i ]);
        }
        printf("\n# Additional Section:\n");
        for (i = 0; i < result->r_arcount; i++) {
            print_rr(&result->r_additional[ i ]);
        }
    }

    if (test_cache) {
        printf("Testing cache\n");
        while (!dnsr_result_expired(dnsr, result)) {
            printf("result not expired - sleeping 30 seconds\n");
            sleep(30);
        }
        printf("result expired\n");
    }

    dnsr_free_result(result);
    dnsr_free(dnsr);

    exit(0);
}
