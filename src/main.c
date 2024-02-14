#include "hv/hv.h"
#include "utils/fileutils.h"

#define CONFIG_FILE "config.json"
#define CORE_FILE "core.json"

void default_logger_handle(int loglevel, const char *buf, int len)
{
    stdout_logger(loglevel, buf, len);
    file_logger(loglevel, buf, len); // writes to default file
}

int main(int argc, char **argv)
{

    hv_mkdir_p("log");
    hlog_set_file("log/core.log");
    logger_set_handler(hv_default_logger(), default_logger_handle);

    // read core file
    char *core_file_content = readFile(CORE_FILE);
    if (core_file_content == NULL)
    {
        LOGF("Could not read core file \"%s\" ", CORE_FILE);
        exit(1);
    }

    printf(core_file_content, NULL);
}