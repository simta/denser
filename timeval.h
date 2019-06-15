#ifndef DENSER_TIMEVAL_H
#define DENSER_TIMEVAL_H

#include <sys/time.h>

int tv_add(struct timeval *tp1, struct timeval *tp2, struct timeval *result);
int tv_sub(struct timeval *tp1, struct timeval *tp2, struct timeval *result);
int tv_lt(struct timeval *tp1, struct timeval *tp2);
int tv_gt(struct timeval *tp1, struct timeval *tp2);

#endif /* DENSER_TIMEVAL_H */
