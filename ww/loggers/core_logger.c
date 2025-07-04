#include "core_logger.h"


struct logger_s;
static logger_t *logger = NULL;

void coreloggerDestroy(void)
{
    if (logger)
    {
        loggerSyncFile(logger);
        loggerDestroy(logger);
        logger = NULL;
    }
}

static void coreLoggerHandleOnlyStdStream(int loglevel, const char *buf, int len)
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

static void coreLoggerHandleWithStdStream(int loglevel, const char *buf, int len)
{
    coreLoggerHandleOnlyStdStream(loglevel, buf, len);
    loggerWrite(logger, buf, len);
}

static void coreLoggerHandle(int loglevel, const char *buf, int len)
{
    discard loglevel;
    loggerWrite(logger, buf, len);
}

logger_t *getCoreLogger(void)
{
    return logger;
}
void setCoreLogger(logger_t *newlogger)
{
    assert(logger == NULL);
    logger = newlogger;
}

logger_t *createCoreLogger(const char *log_file, bool console)
{   
    assert(logger == NULL);
    logger = loggerCreate();
    bool path_accepted = loggerSetFile(logger, log_file);
    if (console)
    {
        if (path_accepted)
        {
            loggerSetHandler(logger, coreLoggerHandleWithStdStream);
        }
        else
        {

            loggerSetHandler(logger, coreLoggerHandleOnlyStdStream);
        }
    }
    else if (path_accepted)
    {
        loggerSetHandler(logger, coreLoggerHandle);
    }

    return logger;
}

logger_handler getCoreLoggerHandle(void)
{
    return loggerGetHandle(logger);
}
