#include "sync_dns.h"
#include "loggers/dns_logger.h"

bool resolveContextSync(socket_context_t *sctx)
{
    // please check these before calling this function -> more performance
    assert(sctx->address_type == kSatDomainName && sctx->domain_resolved == false && sctx->domain != NULL);
    // we need to get and set port again because resolved ip can be v6/v4 which have different sizes
    uint16_t old_port = sockaddr_port(&(sctx->addr));
#ifdef PROFILE
    struct timeval tv1, tv2;
    gettimeofday(&tv1, NULL);
#endif
    /* resolve domain */
    {
        if (sockaddr_set_ipport(&(sctx->addr), sctx->domain, old_port) != 0)
        {
            LOGE("SyncDns: resolve failed  %s", sctx->domain);
            return false;
        }
        if (logger_will_write_level(getDnsLogger(), (log_level_e) LOG_LEVEL_INFO))
        {
            char ip[64];
            sockaddr_str(&(sctx->addr), ip, 64);
            LOGI("SyncDns: %s resolved to %s", sctx->domain, ip);
        }
    }
#ifdef PROFILE
    gettimeofday(&tv2, NULL);
    double time_spent = (double) (tv2.tv_usec - tv1.tv_usec) / 1000000 + (double) (tv2.tv_sec - tv1.tv_sec);
    LOGD("SyncDns: dns resolve took %lf sec", time_spent);
#endif

    sctx->domain_resolved = true;
    return true;
}