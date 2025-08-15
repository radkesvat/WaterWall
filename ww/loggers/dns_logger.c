#include "dns_logger.h"


struct logger_s;
static logger_t *dns_logger = NULL;

void dnsloggerDestroy(void)
{
    if (dns_logger)
    {
        loggerSyncFile(dns_logger);
        loggerDestroy(dns_logger);
        dns_logger = NULL;
    }
}

static void dnsLoggerHandleOnlyStdStream(int loglevel, const char *buf, int len)
{
    switch (loglevel)
    {
    case LOG_LEVEL_WARN:
    case LOG_LEVEL_ERROR:
    case LOG_LEVEL_FATAL:
        stderrLogger(loglevel, buf, len);
        break;
    default:
        stdoutLogger(loglevel, buf, len);
        break;
    }
}

static void dnsLoggerHandleWithStdStream(int loglevel, const char *buf, int len)
{
    dnsLoggerHandleOnlyStdStream(loglevel, buf, len);
    loggerWrite(dns_logger, buf, len);
}


static void dnsLoggerHandle(int loglevel, const char *buf, int len)
{
    discard loglevel;
    loggerWrite(dns_logger, buf, len);
}

logger_t *getDnsLogger(void)
{
    return dns_logger;
}
void setDnsLogger(logger_t *newlogger)
{
    assert(dns_logger == NULL);
    dns_logger = newlogger;
}

logger_t *createDnsLogger(const char *log_file, bool console)
{
    assert(dns_logger == NULL);
    dns_logger = loggerCreate();
    bool path_accepted = loggerSetFile(dns_logger, log_file);
    if (console)
    {
        if (path_accepted)
        {
            loggerSetHandler(dns_logger, dnsLoggerHandleWithStdStream);
        }
        else
        {

            loggerSetHandler(dns_logger, dnsLoggerHandleOnlyStdStream);
        }
    }
    else if (path_accepted)
    {
        loggerSetHandler(dns_logger, dnsLoggerHandle);
    }
    return dns_logger;
}

logger_handler getDnsLoggerHandle(void)
{
    return loggerGetHandle(dns_logger);
}
