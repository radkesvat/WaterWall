#include "internal_logger.h"

struct logger_s;
static logger_t *logger = NULL;

static void destroyInternalLogger(void)
{
    if (logger)
    {
        loggerSyncFile(logger);
        loggerDestroy(logger);
        logger = NULL;
    }
}

static void internalLoggerHandleWithStdStream(int loglevel, const char *buf, int len)
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

static void internalLoggerHandle(int loglevel, const char *buf, int len)
{
    (void) loglevel;
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
    logger = loggerCreate();
    loggerSetFile(logger, log_file);
    if (console)
    {
        loggerSetHandler(logger, internalLoggerHandleWithStdStream);
    }
    else
    {
        loggerSetHandler(logger, internalLoggerHandle);
    }

    atexit(destroyInternalLogger);
    return logger;
}

logger_handler getInternalLoggerHandle(void)
{
    return loggerGetHandle(logger);
}
