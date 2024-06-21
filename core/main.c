#include "config_file.h"
#include "core_settings.h"
#include "hbase.h"
#include "loggers/core_logger.h"
#include "managers/node_manager.h"
#include "managers/socket_manager.h"
#include "os_helpers.h"
#include "static_tunnels.h"
#include "utils/fileutils.h"
#include "utils/stringutils.h"
#include "ww.h"

int main(void)
{
    // test ASAN works -_-
    // int test[3] = {0};
    // printf("hello world %d", test[4]);

    static const char *core_file_name    = "core.json";
    char              *core_file_content = readFile(core_file_name);
    
    if (core_file_content == NULL)
    {
        fprintf(stderr, "Waterwall version %s\nCould not read core settings file \"%s\" \n",
                TOSTRING(WATERWALL_VERSION), core_file_name);
        exit(1);
    }
    parseCoreSettings(core_file_content);
    free(core_file_content);

    //  [Runtime setup]
    hv_mkdir_p(getCoreSettings()->log_path);

    ww_construction_data_t runtime_data = {
        .workers_count       = getCoreSettings()->workers_count,
        .ram_profile         = getCoreSettings()->ram_profile,
        .core_logger_data    = (logger_construction_data_t){.log_file_path = getCoreSettings()->core_log_file_fullpath,
                                                            .log_level     = getCoreSettings()->core_log_level,
                                                            .log_console   = getCoreSettings()->core_log_console},
        .network_logger_data = (logger_construction_data_t){.log_file_path = getCoreSettings()->network_log_file_fullpath,
                                                            .log_level     = getCoreSettings()->network_log_level,
                                                            .log_console   = getCoreSettings()->network_log_console},
        .dns_logger_data     = (logger_construction_data_t){.log_file_path = getCoreSettings()->dns_log_file_fullpath,
                                                            .log_level     = getCoreSettings()->dns_log_level,
                                                            .log_console   = getCoreSettings()->dns_log_console},
    };

    // core logger is available after ww setup
    createWW(runtime_data);

    LOGI("Starting Waterwall version %s", TOSTRING(WATERWALL_VERSION));
    LOGI("Parsing core file complete");
    increaseFileLimit();
    loadStaticTunnelsIntoCore();

    //  [Parse ConfigFiles]
    //  TODO (config file) this currently runs only 1 config file
    {
        c_foreach(k, vec_config_path_t, getCoreSettings()->config_paths)
        {
            // read config file
            LOGD("Core: begin parsing config file \"%s\"", *k.ref);
            config_file_t *cfile = parseConfigFile(*k.ref);

            if (cfile == NULL)
            {
                LOGF("Core: could not read file \"%s\" ", *k.ref);
                exit(1);
            }

            LOGI("Core: parsing config file \"%s\" complete", *k.ref);
            runConfigFile(cfile);
            break;
        }
    }
    LOGD("Core: starting workers ...");
    startSocketManager();
    runMainThread();
}
