#include "loggers/network_logger.h"

#include "IpManipulator/structure.h"

enum
{
    kLogCaptureCapacity = 8192
};

static char   log_capture[kLogCaptureCapacity];
static size_t log_capture_len;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void captureLog(int log_level, const char *buf, int len)
{
    discard log_level;

    if (buf == NULL || len <= 0 || log_capture_len >= sizeof(log_capture) - 1U)
    {
        return;
    }

    size_t copy_len = min((size_t) len, sizeof(log_capture) - log_capture_len - 1U);
    memoryCopy(log_capture + log_capture_len, buf, copy_len);
    log_capture_len += copy_len;
    log_capture[log_capture_len] = '\0';
}

static uint32_t countSubstring(const char *text, const char *needle)
{
    uint32_t    count = 0;
    const char *match = text;
    size_t      len   = strlen(needle);

    while ((match = strstr(match, needle)) != NULL)
    {
        count += 1U;
        match += len;
    }
    return count;
}

int main(void)
{
    logger_t *logger = loggerCreate();
    require(logger != NULL, "failed to create network logger");
    loggerSetHandler(logger, captureLog);
    setNetworkLogger(logger);

    tunnel_t *t = memoryAllocateAlignedZero(sizeof(*t) + sizeof(ipmanipulator_tstate_t), kCpuLineCacheSize);
    require(t != NULL, "failed to allocate IpManipulator test tunnel");
    t->tstate_size = sizeof(ipmanipulator_tstate_t);

    ipmanipulator_tstate_t *state = tunnelGetState(t);
    atomicLogRateLimiterInitialize(&state->worker_mismatch_guidance_limiter);

    ipmanipulator_delay_barrier_t barrier        = {.deadline_ms = 1, .owner_wid = 1};
    bool                          needs_schedule = false;

    for (wid_t packet_wid = 2; packet_wid <= 3; ++packet_wid)
    {
        line_t *packet_line = memoryAllocateZero(sizeof(*packet_line));
        sbuf_t *packet      = sbufCreate(1);
        require(packet_line != NULL && packet != NULL, "failed to allocate mismatch packet fixture");
        packet_line->wid = packet_wid;
        require(! ipmanipulatorDelayBarrierTryEnqueue(
                    t, kIpManipulatorDelayBarrierOverlapSni, &barrier, packet_line, packet, false, &needs_schedule),
                "cross-worker packet unexpectedly joined the delay barrier");
        sbufDestroy(packet);
        memoryFree(packet_line);
    }

    require(countSubstring(log_capture, "overlap-sni abandoned delayed packet barrier for one flow") == 2,
            "technical mismatch log was rate-limited or missing");
    require(strstr(log_capture, "packet segment arrived on worker 2") != NULL,
            "technical mismatch log omitted the packet worker");
    require(strstr(log_capture, "retained state belongs to worker 1") != NULL,
            "technical mismatch log omitted the state owner worker");
    require(strstr(log_capture, "releasing retained traffic through normal forwarding") != NULL,
            "technical mismatch log did not explain fail-open behavior");
    require(countSubstring(log_capture, "configuration guidance") == 1,
            "one-worker guidance was not independently rate-limited");
    require(strstr(log_capture, "set misc.workers to 1 in core.json") != NULL,
            "one-worker guidance omitted the actionable setting");

    memoryFreeAligned(t);
    networkloggerDestroy();
    return 0;
}
