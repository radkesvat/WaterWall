#ifndef WW_CONFIG_H_
#define WW_CONFIG_H_


#define WW_VERSION_MAJOR    1
#define WW_VERSION_MINOR    3
#define WW_VERSION_PATCH    2


#ifndef HAVE_STDBOOL_H
#define HAVE_STDBOOL_H 1
#endif

#ifndef HAVE_STDINT_H
#define HAVE_STDINT_H 1
#endif

#ifndef HAVE_STDATOMIC_H
#define HAVE_STDATOMIC_H 1
#endif

#ifndef HAVE_SYS_TYPES_H
#define HAVE_SYS_TYPES_H 1
#endif

#ifndef HAVE_SYS_STAT_H
#define HAVE_SYS_STAT_H 1
#endif

#ifndef HAVE_SYS_TIME_H
#define HAVE_SYS_TIME_H 1
#endif

#ifndef HAVE_FCNTL_H
#define HAVE_FCNTL_H 1
#endif

#ifndef HAVE_PTHREAD_H
#define HAVE_PTHREAD_H 1
#endif

#ifndef HAVE_ENDIAN_H
#define HAVE_ENDIAN_H 0
#endif

#ifndef HAVE_SYS_ENDIAN_H
#define HAVE_SYS_ENDIAN_H 0
#endif

#ifndef HAVE_GETTID
#define HAVE_GETTID 0
#endif

#ifndef HAVE_STRLCPY
#define HAVE_STRLCPY 0
#endif

#ifndef HAVE_STRLCAT
#define HAVE_STRLCAT 0
#endif

#ifndef HAVE_CLOCK_GETTIME
#define HAVE_CLOCK_GETTIME 1
#endif

#ifndef HAVE_GETTIMEOFDAY
#define HAVE_GETTIMEOFDAY 1
#endif

#ifndef HAVE_PTHREAD_SPIN_LOCK
#define HAVE_PTHREAD_SPIN_LOCK 1
#endif

#ifndef HAVE_PTHREAD_MUTEX_TIMEDLOCK
#define HAVE_PTHREAD_MUTEX_TIMEDLOCK 1
#endif

#ifndef HAVE_SEM_TIMEDWAIT
#define HAVE_SEM_TIMEDWAIT 1
#endif

#ifndef HAVE_PIPE
#define HAVE_PIPE 0
#endif

#ifndef HAVE_SOCKETPAIR
#define HAVE_SOCKETPAIR 0
#endif

#ifndef HAVE_EVENTFD
#define HAVE_EVENTFD 0
#endif

#ifndef HAVE_SETPROCTITLE
#define HAVE_SETPROCTITLE 0
#endif


/* #undef ENABLE_UDS */
/* #undef USE_MULTIMAP */

#define WITH_WEPOLL    1


#define FNV_HASH 100
#define KOMI_HASH 200
#define WHASH_ALG KOMI_HASH


#define MEM128_BUF_OPTIMIZE 0


enum ram_profiles_e
{
    kRamProfileInvalid  = 0,
    kRamProfileS1Memory = 1,
    kRamProfileS2Memory = 8,
    kRamProfileM1Memory = 16 * 8 * 1,
    kRamProfileM2Memory = 16 * 8 * 2,
    kRamProfileL1Memory = 16 * 8 * 3,
    kRamProfileL2Memory = 16 * 8 * 4
};



#endif // WW_CONFIG_H_
