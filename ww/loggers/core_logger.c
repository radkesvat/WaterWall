#include "internal_logger.h"
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

struct logger_s;
static logger_t *logger = NULL;

static void destroyCoreLogger(void)
{
    if (logger)
    {
        syncLoggerFile(logger);
        destroyLogger(logger);
        logger = NULL;
    }
}

static void coreLoggerHandleWithStdStream(int loglevel, const char *buf, int len)
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
    writeLogFile(logger, buf, len);
}

static void coreLoggerHandle(int loglevel, const char *buf, int len)
{
    (void) loglevel;
    writeLogFile(logger, buf, len);
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
    logger = createLogger();
    setLoggerFile(logger, log_file);
    if (console)
    {
        setLoggerHandler(logger, coreLoggerHandleWithStdStream);
    }
    else
    {
        setLoggerHandler(logger, coreLoggerHandle);
    }

    atexit(destroyCoreLogger);
    return logger;
}

logger_handler getCoreLoggerHandle(void)
{
    return getLoggerHandle(logger);
}
