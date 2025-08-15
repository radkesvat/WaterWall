#include "internal_logger.h"

struct logger_s;
static logger_t *internal_logger = NULL;

void internaloggerDestroy(void)
{
    if (internal_logger)
    {
        loggerSyncFile(internal_logger);
        loggerDestroy(internal_logger);
        internal_logger = NULL;
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
    loggerWrite(internal_logger, buf, len);
}

static void internalLoggerHandle(int loglevel, const char *buf, int len)
{
    discard loglevel;
    loggerWrite(internal_logger, buf, len);
}

logger_t *getInternalLogger(void)
{
    return internal_logger;
}

void setInternalLogger(logger_t *newlogger)
{
    assert(internal_logger == NULL);
    internal_logger = newlogger;
}

logger_t *createInternalLogger(const char *log_file, bool console)
{
    assert(internal_logger == NULL);
    internal_logger             = loggerCreate();
    bool path_accepted = loggerSetFile(internal_logger, log_file);
    if (console)
    {
        if (path_accepted)
        {
            loggerSetHandler(internal_logger, internalLoggerHandleWithStdStream);
        }
        else
        {

            loggerSetHandler(internal_logger, internalLoggerHandleOnlyStdStream);
        }
    }
    else if (path_accepted)
    {
        loggerSetHandler(internal_logger, internalLoggerHandle);
    }

    return internal_logger;
}

logger_handler getInternalLoggerHandle(void)
{
    return loggerGetHandle(internal_logger);
}

logger_t *loggerGetDefaultLogger(void)
{
    if (internal_logger == NULL)
    {
        internal_logger = loggerCreate();
        loggerSetHandler(internal_logger, internalLoggerHandleOnlyStdStream);
    }
    return internal_logger;
}

void loggerDestroyDefaultLogger(void)
{
    if (internal_logger)
    {
        loggerSyncFile(internal_logger);
        loggerDestroy(internal_logger);
        internal_logger = NULL;
    }
}
