#include "core_settings.h"
#include "wwapi.h"

#include "imported_tunnels.h"
#include "loggers/core_logger.h"
#include "node_builder/config_policy.h"
#include "os_helpers.h"
#include "startup_options.h"

// #ifdef COMPILER_MSVC
// #define _CRTDBG_MAP_ALLOC
// #pragma warning (disable: 4005)
// #include <crtdbg.h>
// #endif

static bool waterwallStartupCheckpoint(void)
{
    signalmanagerConsumePendingShutdownSignal();
    return ! applicationShutdownWasRequested();
}

int waterwallInnerMain(int argc, char **argv);

/*
 * Real program logic. On platforms that build the CPU startup guard, the
 * process entry point lives in startup_guard.c (which runs a conservative CPU
 * feature check first) and then calls into here. On platforms where the guard
 * is disabled, the main() at the bottom of this file enters here directly.
 */
int waterwallInnerMain(int argc, char **argv)
{
    waterwall_startup_options_t                startup_options = {0};
    const waterwall_startup_arguments_result_e arguments_result =
        waterwallStartupOptionsParse(argc, argv, &startup_options);
    if (arguments_result != kWaterwallStartupArgumentsRun)
    {
        return arguments_result == kWaterwallStartupArgumentsExitSuccess ? 0 : 1;
    }

    // #ifdef COMPILER_MSVC
    //     _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
    // #endif

    // check address sanitizer works properly
    // int test[3] = {0};
    // printf(" salamati Ali agha Mufasa %d", test[3]);

    initWLibc();

    ww_startup_result_t startup_result = wwStartupSuccess();

    char *core_file_content = waterwallStartupOptionsReadCoreJson(&startup_options);

    if (core_file_content == NULL)
    {
        return 1;
    }
    ww_startup_context_t core_settings_scope = {0};
    wwStartupContextBegin(&core_settings_scope);
    const bool core_settings_parsed = parseCoreSettings(core_file_content);
    startup_result                  = wwStartupContextEnd(&core_settings_scope);
    memoryFree(core_file_content);
    if (! core_settings_parsed)
    {
        waterwallStartupOptionsReportCoreJsonParseFailure(&startup_options);
        destroyCoreSettings();
        return startup_result.exit_code;
    }

    //  [Runtime setup]
    createDirIfNotExists(getCoreSettings()->log_path);

    ww_construction_data_t runtime_data = {
        .workers_count   = getCoreSettings()->workers_count,
        .ram_profile     = getCoreSettings()->ram_profile,
        .mtu_size        = getCoreSettings()->mtu_size,
        .dns_options     = getCoreSettings()->dns_options,
        .domain_strategy = getCoreSettings()->domain_strategy,
        .internal_logger_data =
            (logger_construction_data_t) {.log_file_path = getCoreSettings()->internal_log_file_fullpath,
                                          .log_level     = getCoreSettings()->internal_log_level,
                                          .log_console   = getCoreSettings()->internal_log_console},

        .core_logger_data = (logger_construction_data_t) {.log_file_path = getCoreSettings()->core_log_file_fullpath,
                                                          .log_level     = getCoreSettings()->core_log_level,
                                                          .log_console   = getCoreSettings()->core_log_console},

        .network_logger_data =
            (logger_construction_data_t) {.log_file_path = getCoreSettings()->network_log_file_fullpath,
                                          .log_level     = getCoreSettings()->network_log_level,
                                          .log_console   = getCoreSettings()->network_log_console},

        .dns_logger_data = (logger_construction_data_t) {.log_file_path = getCoreSettings()->dns_log_file_fullpath,
                                                         .log_level     = getCoreSettings()->dns_log_level,
                                                         .log_console   = getCoreSettings()->dns_log_console},
        .application_finalizer = destroyCoreSettings,
    };

    // core logger is available after ww setup
    startup_result = createGlobalState(runtime_data);
    if (UNLIKELY(! wwStartupSucceeded(startup_result)))
    {
        if (GSTATE.application_shutdown == NULL)
        {
            destroyCoreSettings();
            return startup_result.exit_code;
        }
        goto startup_failed;
    }
#if defined(WATERWALL_SYSTEM_LOAD_TEST_HOOKS)
    if (getenv("WATERWALL_TEST_FORCE_SYSTEM_LOAD") != NULL)
    {
        systemLoadSamplerSetForceUnderLoad(GSTATE.system_load, true);
    }
#endif
    nodelibrarySetSearchPath(getCoreSettings()->libs_path);

    LOGI("Starting Waterwall version %s", TOSTRING(WATERWALL_VERSION));
    LOGI("Parsing core settings complete");
    if (getCoreSettings()->try_enabling_bbr)
    {
        tryEnableBbr();
    }

    increaseFileLimit();
    startup_result                            = loadImportedTunnelsIntoCore();
    const bool imported_tunnels_checkpoint_ok = waterwallStartupCheckpoint();
    if (UNLIKELY(! wwStartupSucceeded(startup_result) || ! imported_tunnels_checkpoint_ok))
    {
        goto startup_failed;
    }

    //  [Parse ConfigFiles]
    {
        c_foreach(k, vec_config_path_t, getCoreSettings()->config_paths)
        {
            if (UNLIKELY(! waterwallStartupCheckpoint()))
            {
                goto startup_failed;
            }

            LOGD("Core: begin parsing config file \"%s\"", configPolicyDiagnostic(*k.ref));
            config_file_t *cfile = configfileParse(*k.ref);
            if (cfile == NULL)
            {
                startup_result = wwStartupFailure(1);
            }
            const bool config_parse_checkpoint_ok = waterwallStartupCheckpoint();

            /*
                in case of error in config file, the details are already printed out
            */
            if (! cfile || ! config_parse_checkpoint_ok)
            {
                if (cfile == NULL)
                {
                    assert(! wwStartupSucceeded(startup_result));
                }
                else
                {
                    configfileDestroy(cfile);
                }
                goto startup_failed;
            }

            LOGI("Core: parsing config file \"%s\" complete", configPolicyDiagnostic(*k.ref));
            startup_result                          = nodemanagerRunConfigFile(cfile);
            const bool config_install_checkpoint_ok = waterwallStartupCheckpoint();
            if (UNLIKELY(! wwStartupSucceeded(startup_result) || ! config_install_checkpoint_ok))
            {
                goto startup_failed;
            }
        }
    }

    if (UNLIKELY(! waterwallStartupCheckpoint()))
    {
        goto startup_failed;
    }

    LOGD("Core: starting workers ...");
    startup_result                          = socketmanagerStart();
    const bool socket_manager_checkpoint_ok = waterwallStartupCheckpoint();
    if (UNLIKELY(! wwStartupSucceeded(startup_result) || ! socket_manager_checkpoint_ok))
    {
        goto startup_failed;
    }
    runMainThread();
    return 0;

startup_failed:
    if (! wwStartupSucceeded(startup_result))
    {
        const application_shutdown_request_result_e request_result =
            signalmanagerArbitrateStartupFailure(startup_result.exit_code);
        if (request_result == kApplicationShutdownRequestUnavailable && ! applicationShutdownWasRequested())
        {
            abortProgramNow(startup_result.exit_code);
        }
    }
    else if (! applicationShutdownWasRequested())
    {
        abortProgramNow(1);
    }
    applicationShutdownCoordinate();
    abortProgramNow(startup_result.exit_code);
}

#ifndef WATERWALL_HAS_STARTUP_GUARD
/*
 * The CPU startup guard is disabled on this platform (e.g. MinGW), so the
 * guard's main() in startup_guard.c is never built. Enter the runtime
 * directly; the process will simply crash if the CPU lacks a required
 * instruction set, which is acceptable for these platforms.
 */
int main(int argc, char **argv)
{
    return waterwallInnerMain(argc, argv);
}
#endif
