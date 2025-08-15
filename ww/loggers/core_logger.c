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
    core_logger = loggerCreate();
    bool path_accepted = loggerSetFile(core_logger, log_file);
    if (console)
    {
        if (path_accepted)
        {
            loggerSetHandler(core_logger, coreLoggerHandleWithStdStream);
        }
        else
        {

            loggerSetHandler(core_logger, coreLoggerHandleOnlyStdStream);
        }
    }
    else if (path_accepted)
    {
        loggerSetHandler(core_logger, coreLoggerHandle);
    }

    return core_logger;
}

logger_handler getCoreLoggerHandle(void)
{
    return loggerGetHandle(core_logger);
}
