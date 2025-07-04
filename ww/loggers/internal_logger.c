#include "internal_logger.h"

struct logger_s;
static logger_t *logger = NULL;

void internaloggerDestroy(void)
{
    if (logger)
    {
        loggerSyncFile(logger);
        loggerDestroy(logger);
        logger = NULL;
    }
}

static void internalLoggerHandleOnlyStdStream(int loglevel, const char *buf, int len)
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

static void internalLoggerHandleWithStdStream(int loglevel, const char *buf, int len)
{
    internalLoggerHandleOnlyStdStream(loglevel, buf, len);
    loggerWrite(logger, buf, len);
}

static void internalLoggerHandle(int loglevel, const char *buf, int len)
{
    discard loglevel;
    loggerWrite(logger, buf, len);
}

logger_t *getInternalLogger(void)
{
    return logger;
}

void setInternalLogger(logger_t *newlogger)
{
    assert(logger == NULL);
    logger = newlogger;
}

logger_t *createInternalLogger(const char *log_file, bool console)
{
    assert(logger == NULL);
    logger             = loggerCreate();
    bool path_accepted = loggerSetFile(logger, log_file);
    if (console)
    {
        if (path_accepted)
        {
            loggerSetHandler(logger, internalLoggerHandleWithStdStream);
        }
        else
        {

            loggerSetHandler(logger, internalLoggerHandleOnlyStdStream);
        }
    }
    else if (path_accepted)
    {
        loggerSetHandler(logger, internalLoggerHandle);
    }

    return logger;
}

logger_handler getInternalLoggerHandle(void)
{
    return loggerGetHandle(logger);
}

logger_t *loggerGetDefaultLogger(void)
{
    if (logger == NULL)
    {
        logger = loggerCreate();
        loggerSetHandler(logger, internalLoggerHandleOnlyStdStream);
    }
    return logger;
}

void loggerDestroyDefaultLogger(void)
{
    if (logger)
    {
        loggerSyncFile(logger);
        loggerDestroy(logger);
        logger = NULL;
    }
}
