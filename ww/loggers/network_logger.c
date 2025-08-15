#include "network_logger.h"

struct logger_s;

static logger_t *network_logger = NULL;

void networkloggerDestroy(void)
{
    if (network_logger)
    {
        loggerSyncFile(network_logger);
        loggerDestroy(network_logger);
        network_logger = NULL;
    }
}

static void networkLoggerHandleOnlyStdStream(int loglevel, const char *buf, int len)
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

static void networkLoggerHandleWithStdStream(int loglevel, const char *buf, int len)
{
    networkLoggerHandleOnlyStdStream(loglevel, buf, len);
    loggerWrite(network_logger, buf, len);
}


static void networkLoggerHandle(int loglevel, const char *buf, int len)
{
    discard loglevel;
    loggerWrite(network_logger, buf, len);
}

logger_t *getNetworkLogger(void)
{
    return network_logger;
}
void setNetworkLogger(logger_t *newlogger)
{
    assert(network_logger == NULL);
    network_logger = newlogger;
}

logger_t *createNetworkLogger(const char *log_file, bool console)
{
    assert(network_logger == NULL);
    network_logger = loggerCreate();
    bool path_accepted = loggerSetFile(network_logger, log_file);
    if (console)
    {
        if (path_accepted)
        {
            loggerSetHandler(network_logger, networkLoggerHandleWithStdStream);
        }
        else
        {

            loggerSetHandler(network_logger, networkLoggerHandleOnlyStdStream);
        }
    }
    else if (path_accepted)
    {
        loggerSetHandler(network_logger, networkLoggerHandle);
    }
    return network_logger;
}

logger_handler getNetworkLoggerHandle(void)
{
    return loggerGetHandle(network_logger);
}
