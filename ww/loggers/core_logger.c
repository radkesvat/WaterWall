#include "core_logger.h"

struct logger_s;
static logger_t *core_logger = NULL;

void coreloggerDestroy(void)
{
    if (core_logger)
    {
        loggerSyncFile(core_logger);
        loggerDestroy(core_logger);
        core_logger = NULL;
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
    loggerWrite(core_logger, buf, len);
}

static void coreLoggerHandle(int loglevel, const char *buf, int len)
{
    discard loglevel;
    loggerWrite(core_logger, buf, len);
}

logger_t *getCoreLogger(void)
{
    return core_logger;
}
void setCoreLogger(logger_t *newlogger)
{
    assert(core_logger == NULL);
    core_logger = newlogger;
}

logger_t *createCoreLogger(const char *log_file, bool console)
{
    assert(core_logger == NULL);
    logger_t *logger = loggerCreate();
    if (UNLIKELY(logger == NULL))
    {
        return NULL;
    }

    bool path_accepted = ((log_file != NULL) && loggerSetFile(logger, log_file)) != 0;
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
    else
    {
        // no logger
    }

    core_logger = logger;
    return logger;
}

logger_handler getCoreLoggerHandle(void)
{
    return loggerGetHandle(core_logger);
}
