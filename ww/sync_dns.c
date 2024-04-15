#include "sync_dns.h"
#include "loggers/dns_logger.h"
#include "types.h"

static inline bool resolve(socket_context_t *dest)
{
    // we need to get and set port again because resolved ip can be v6/v4 which have different sizes
    uint16_t old_port = sockaddr_port(&(dest->addr));
#ifdef PROFILE
    struct timeval tv1, tv2;
    gettimeofday(&tv1, NULL);
#endif
    /* resolve domain */
    {
        if (sockaddr_set_ip_port(&(dest->addr), dest->domain, old_port) != 0)
        {
            LOGE("Connector: resolve failed  %s", dest->domain);
            return false;
        }
        if (logger_will_write_level(LOG_LEVEL_INFO))
        {
            char ip[60];
            sockaddr_str(&(dest->addr), ip, 60);
            LOGI("Connector: %s resolved to %s", dest->domain, ip);
        }
    }
#ifdef PROFILE
    gettimeofday(&tv2, NULL);
    double time_spent = (double) (tv2.tv_usec - tv1.tv_usec) / 1000000 + (double) (tv2.tv_sec - tv1.tv_sec);
    LOGD("Connector: dns resolve took %lf sec", time_spent);
#endif

    dest->resolved = true;
    return true;
}

bool resolveContextSync(socekt_context_t *s_ctx)
{
    // please check these before calling this function -> more performance
    assert(s_ctx.atype == SAT_DOMAINNAME && s_ctx.resolved == false && dest->domain != NULL);
    return resolve(s_ctx);
}