/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include <inttypes.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "denser.h"
#include "internal.h"

/*
 * Creates a new DNSR structure which will be used for all future denser
 * calls.  This only fails on system error.  Other functions have been moved
 * out of this routine so they can provide better error reporting via
 * the DNSR->d_errno.
 *
 * The returned dnsr handle is configured for recursion.  Can be changed with
 * dnsr_config( ).
 *
 * Return Values:
 *      DNSR *  success
 *      NULL    error - check errno
 */

DNSR *
dnsr_new(void) {
    DNSR *         dnsr;
    struct timeval tv;

    if (gettimeofday(&tv, NULL) != 0) {
        return (NULL);
    }
    srand((unsigned int)getpid() ^ tv.tv_usec ^ tv.tv_sec);

    if ((dnsr = calloc(1, sizeof(DNSR))) == NULL) {
        return (NULL);
    }

    dnsr->d_nsresp = -1;

    if ((dnsr->d_fd6 = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
        DEBUG(perror("dnsr_open: AF_INET6 socket"));
    }

    if ((dnsr->d_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        DEBUG(perror("dnsr_open: AF_INET socket"));
    }

    if ((dnsr->d_fd6 < 0) && (dnsr->d_fd < 0)) {
        free(dnsr);
        return (NULL);
    }

    /* XXX - do we need to check error here? */
    dnsr_config(dnsr, DNSR_FLAG_RECURSION, DNSR_FLAG_ON);

    return (dnsr);
}

void
dnsr_free(DNSR *dnsr) {
    if (dnsr == NULL) {
        return;
    }
    if (dnsr->d_fd >= 0) {
        if (close(dnsr->d_fd) != 0) {
            DEBUG(perror("dnsr_free: close"));
        }
    }
    if (dnsr->d_fd6 >= 0) {
        if (close(dnsr->d_fd6) != 0) {
            DEBUG(perror("dnsr_free: close"));
        }
    }
    free(dnsr);
}
