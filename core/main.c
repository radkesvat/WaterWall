#include "config_file.h"
#include "core_settings.h"
#include "eventloop_mem.h"
#include "loggers/core_logger.h"
#include "managers/node_manager.h"
#include "managers/socket_manager.h"
#include "os_helpers.h"
#include "imported_tunnels.h"
#include "utils/fileutils.h"
#include "utils/stringutils.h"
#include "worker.h"

int main(void)
{
    // check address sanitizer works properly
    // int test[3] = {0};
    // printf("hello world %d", test[3]);

    initWLibc();

    static const char *core_file_name    = "core.json";
    char              *core_file_content = readFile(core_file_name);

    if (core_file_content == NULL)
    {
        printError("Waterwall version %s\nCould not read core settings file \"%s\" \n",
                TOSTRING(WATERWALL_VERSION), core_file_name);
        exit(1);
    }
    parseCoreSettings(core_file_content);
    memoryFree(core_file_content);

    //  [Runtime setup]
    createDirIfNotExists(getCoreSettings()->log_path);

    

    ww_construction_data_t runtime_data = {
        .workers_count       = getCoreSettings()->workers_count,
        .ram_profile         = getCoreSettings()->ram_profile,
        .core_logger_data    = (logger_construction_data_t) {.log_file_path = getCoreSettings()->core_log_file_fullpath,
                                                             .log_level     = getCoreSettings()->core_log_level,
                                                             .log_console   = getCoreSettings()->core_log_console},
        .network_logger_data = (logger_construction_data_t) {.log_file_path = getCoreSettings()->network_log_file_fullpath,
                                                             .log_level     = getCoreSettings()->network_log_level,
                                                             .log_console   = getCoreSettings()->network_log_console},
        .dns_logger_data     = (logger_construction_data_t) {.log_file_path = getCoreSettings()->dns_log_file_fullpath,
                                                             .log_level     = getCoreSettings()->dns_log_level,
                                                             .log_console   = getCoreSettings()->dns_log_console},
    };

    // core logger is available after ww setup
    createGlobalState(runtime_data);

    LOGI("Starting Waterwall version %s", TOSTRING(WATERWALL_VERSION));
    LOGI("Parsing core file complete");
    increaseFileLimit();
    loadStaticTunnelsIntoCore();

    //  [Parse ConfigFiles]
    {
        c_foreach(k, vec_config_path_t, getCoreSettings()->config_paths)
        {
            LOGD("Core: begin parsing config file \"%s\"", *k.ref);
            config_file_t *cfile = parseConfigFile(*k.ref);

            /*
                in case of error in config file, the details are already printed out and the
                program will not reach this line.
            */

            LOGI("Core: parsing config file \"%s\" complete", *k.ref);
            runConfigFile(cfile);
        }
    }

    LOGD("Core: starting workers ...");
    startSocketManager();
    runMainThread();
}
