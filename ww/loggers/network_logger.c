#include "network_logger.h"
#include "hlog.h"
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

struct logger_s;

static logger_t *logger = NULL;

static void destroyNetworkLogger(void)
{
    if (logger)
    {
        logger_fsync(logger);
        logger_destroy(logger);
        logger = NULL;
    }
}

static void networkLoggerHandleWithStdStream(int loglevel, const char *buf, int len)
{
    switch (loglevel)
    {
    case LOG_LEVEL_WARN:
    case LOG_LEVEL_ERROR:
    case LOG_LEVEL_FATAL:
        stderr_logger(loglevel, buf, len);
        break;
    default:
        stdout_logger(loglevel, buf, len);
        break;
    }
    logfile_write(logger, buf, len);
}

static void networkLoggerHandle(int loglevel, const char *buf, int len)
{
    (void) loglevel;
    logfile_write(logger, buf, len);
}

logger_t *getNetworkLogger(void)
{
    return logger;
}
void setNetworkLogger(logger_t *newlogger)
{
    assert(logger == NULL);
    logger = newlogger;
}

logger_t *createNetworkLogger(const char *log_file, bool console)
{
    assert(logger == NULL);
    logger = logger_create();
    logger_set_file(logger, log_file);
    if (console)
    {
        logger_set_handler(logger, networkLoggerHandleWithStdStream);
    }
    else
    {
        logger_set_handler(logger, networkLoggerHandle);
    }

    atexit(destroyNetworkLogger);
    return logger;
}
