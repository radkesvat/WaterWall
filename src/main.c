#include "hv/hv.h"
#include "utils/fileutils.h"
#include "utils/stringutils.h"
#include "core_settings.h"
#include "loggers/dns_logger.h"
#include "loggers/network_logger.h"
#include "loggers/core_logger.h"

#define CONFIG_FILE "config.json"
#define CORE_FILE "core.json"

int main(int argc, char **argv)
{

    initCoreSettings();
    // read core file
    char *core_file_content = readFile(CORE_FILE);
    if (core_file_content == NULL)
    {
        fprintf(stderr, "Could not read core file \"%s\" ", CORE_FILE);
        exit(1);
    }
    parseCoreSettings(core_file_content);

    //  [Logger setup]
    {
        hv_mkdir_p(getCoreSettings()->log_path);
        char *core_log_file_path = concat(getCoreSettings()->log_path, getCoreSettings()->core_log_file);
        char *network_log_file_path = concat(getCoreSettings()->log_path, getCoreSettings()->network_log_file);
        char *dns_log_file_path = concat(getCoreSettings()->log_path, getCoreSettings()->dns_log_file);
        initCoreLogger(core_log_file_path);
        initNetworkLogger(network_log_file_path);
        initDnsLogger(dns_log_file_path);
        free(core_log_file_path);
        free(network_log_file_path);
        free(dns_log_file_path);
        // TODO log level
    }

    LOGW("Parsing core file complete");

    // [Required Files]

    // read config file
    char *config_file_content = readFile(CONFIG_FILE);
    if (config_file_content == NULL)
    {
        LOGF("Could not read core file \"%s\" ", CONFIG_FILE);
        exit(1);
    }
    LOGI("Parsing config file complete");
}