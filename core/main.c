#include "api.h"
#include "utils/fileutils.h"
#include "utils/stringutils.h"
#include "managers/socket_manager.h"
#include "managers/node_manager.h"
#include "core_settings.h"
#include "static_tunnels.h"
#include "loggers/dns_logger.h"
#include "loggers/network_logger.h"
#include "loggers/core_logger.h"

#define CORE_FILE "core.json"

int main(int argc, char **argv)
{

    initCoreSettings();
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
        createWW(
            core_log_file_path,
            network_log_file_path,
            dns_log_file_path,
            getCoreSettings()->core_log_level,
            getCoreSettings()->network_log_level,
            getCoreSettings()->dns_log_level,
            getCoreSettings()->threads);

        free(core_log_file_path);
        free(network_log_file_path);
        free(dns_log_file_path);
    }
    LOGI("Starting Waterwall version %s", TOSTRING(WATERWALL_VERSION));
    LOGI("Parsing core file complete");

    loadStaticTunnelsIntoCore();

    //  [Parse ConfigFiles]
    //  TODO this currently only runs 1 config file
    {
        c_foreach(k, vec_config_path_t, getCoreSettings()->config_paths)
        {
            // read config file
            LOGD("Begin parsing config file \"%s\"", *k.ref);
            config_file_t *cfile = parseConfigFile(*k.ref);

            if (cfile == NULL)
            {
                LOGF("Could not read core file \"%s\" ", *k.ref);
                exit(1);
            }

            LOGI("Parsing config file \"%s\" complete", *k.ref);
            runConfigFile(cfile);
            LOGD("Spawning accept thread spawned...", *k.ref);
            startSocketManager();
            LOGD("Starting the eventloop...", *k.ref);
            hloop_run(loops[0]);
            LOGW("MainThread moved out of eventloop", *k.ref);


        }
    }
}