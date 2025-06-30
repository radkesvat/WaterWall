#include "dns_logger.h"


struct logger_s;
static logger_t *logger = NULL;

static void destroyDnsLogger(void)
{
    if (logger)
    {
        loggerSyncFile(logger);
        loggerDestroy(logger);
        logger = NULL;
    }
}

static void dnsLoggerHandleWithStdStream(int loglevel, const char *buf, int len)
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
    loggerWrite(logger, buf, len);
}

static void dnsLoggerHandle(int loglevel, const char *buf, int len)
{
    discard loglevel;
    loggerWrite(logger, buf, len);
}

logger_t *getDnsLogger(void)
{
    return logger;
}
void setDnsLogger(logger_t *newlogger)
{
    assert(logger == NULL);
    logger = newlogger;
}

logger_t *createDnsLogger(const char *log_file, bool console)
{
    assert(logger == NULL);
    logger = loggerCreate();
    loggerSetFile(logger, log_file);
    if (console)
    {
        loggerSetHandler(logger, dnsLoggerHandleWithStdStream);
    }
    else
    {
        loggerSetHandler(logger, dnsLoggerHandle);
    }

    return logger;
}

logger_handler getDnsLoggerHandle(void)
{
    return loggerGetHandle(logger);
}
