#include "sync_dns.h"
#include "loggers/dns_logger.h"
#include "wlibc.h"
#include "wsocket.h"

bool resolveContextSync(address_context_t *sctx)
{
    // please check these before calling this function -> more performance
    assert(sctx->type_ip == false && sctx->domain != NULL);
    // we need to get and set port again because resolved ip can be v6/v4 which have different sizes

#ifdef PROFILE
    struct timeval tv1, tv2;
    getTimeOfDay(&tv1, NULL);
#endif
    /* resolve domain */
    {
        sockaddr_u temp;
        if (sockaddrSetIp(&temp, sctx->domain) != 0)
        {
            LOGE("SyncDns: resolve failed  %s", sctx->domain);
            return false;
        }
        ipAddressFromSockAddr(&(sctx->ip_address), &temp);

        if (loggerCheckWriteLevel(getDnsLogger(), (log_level_e) LOG_LEVEL_INFO))
        {
            char ip[64];
            sockaddrStr(&(temp), ip, 64);
            LOGI("SyncDns: %s resolved to %s", sctx->domain, ip);
        }
    }
#ifdef PROFILE
    getTimeOfDay(&tv2, NULL);
    double time_spent = (double) (tv2.tv_usec - tv1.tv_usec) / 1000000 + (double) (tv2.tv_sec - tv1.tv_sec);
    LOGD("SyncDns: dns resolve took %lf sec", time_spent);
#endif

    sctx->type_ip = false;
    return true;
}
