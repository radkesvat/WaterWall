#include "hv/hv.h"
#include "utils/fileutils.h"
#include "loggers/dns_logger.h"
#include "loggers/network_logger.h"
#include "loggers/core_logger.h"

#define CONFIG_FILE "config.json"
#define CORE_FILE "core.json"

int main(int argc, char **argv)
{
    hv_mkdir_p("log");

    // TODO customize from core json file
    //  [Logger setup]
    initCoreLogger("log/core.log");
    initNetworkLogger("log/network.log");
    initDnsLogger("log/network.log");

    // [Required Files]
    // read core file
    char *core_file_content = readFile(CORE_FILE);
    if (core_file_content == NULL)
    {
        LOGF("Could not read core file \"%s\" ", CORE_FILE);
        exit(1);
    }
    LOGI("Parsing core file complete");

    // read config file
    char *config_file_content = readFile(CONFIG_FILE);
    if (config_file_content == NULL)
    {
        LOGF("Could not read core file \"%s\" ", CONFIG_FILE);
        exit(1);
    }
    LOGI("Parsing config file complete");
}