#include "core_logger.h"
#include "hlog.h"
#include "hmutex.h"
#include "htime.h"
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
        logger_fsync(logger);
        logger_destroy(logger);
        logger = NULL;
    }
}

static void networkLoggerHandleWithStdStream(int loglevel, const char *buf, int len)
{
    if (loglevel == LOG_LEVEL_ERROR || loglevel == LOG_LEVEL_FATAL)
    {
        stderr_logger(loglevel, buf, len);
    }
    else
    {
        stdout_logger(loglevel, buf, len);
    }
    logfile_write(logger, buf, len);
}

static void networkLoggerHandle(int loglevel, const char *buf, int len)
{
    (void) loglevel;
    logfile_write(logger, buf, len);
}

logger_t *getCoreLogger()
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

    atexit(destroyCoreLogger);
    return logger;
}

core_logger_handle_t getCoreLoggerHandle()
{
    return logger_handle(logger);
}