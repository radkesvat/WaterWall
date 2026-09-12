#include "core_settings.h"
#include "wwapi.h"

#include "imported_tunnels.h"
#include "loggers/core_logger.h"
#include "node_builder/config_policy.h"
#include "os_helpers.h"
#include "startup_options.h"

#ifdef OS_WIN
#include "devices/tun/tun_windows_dns.h"
#include "devices/windows_session_effects.h"
#include "global_state_internal.h"
#include "lifecycle_capabilities_windows.h"
#include "lifecycle_windows.h"
#endif

// #ifdef COMPILER_MSVC
// #define _CRTDBG_MAP_ALLOC
// #pragma warning (disable: 4005)
// #include <crtdbg.h>
// #endif

#ifdef OS_WIN
static HANDLE completion_event;
static void   waterwallOrderlyReturn(void)
{
    if (completion_event != NULL)
    {
        SetEvent(completion_event);
        CloseHandle(completion_event);
    }
}
#endif

static bool waterwallStartupCheckpoint(void)
{
#ifdef OS_WIN
    waterwallLifecycleCheckpoint();
#endif
    signalmanagerConsumePendingShutdownSignal();
    return ! applicationShutdownWasRequested();
}

static void waterwallApplicationFinalize(void)
{
#ifdef OS_WIN
    if (! tunWindowsDnsShutdown())
    {
        applicationShutdownRecordFailure(1, kApplicationShutdownReasonSubsystemFailure);
    }
    tunWindowsDnsSetStartupStopEvent(NULL);
    waterwallLifecycleDestroy();
#endif
    destroyCoreSettings();
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
    waterwall_handoff_t handoff     = {.fd = -1};
    const int           handoff_res = waterwallStartupHandoffExtract(&argc, argv, &handoff);
    if (handoff_res < 0)
    {
        waterwallStartupHandoffCleanup(&handoff);
        return 1;
    }

#ifdef OS_WIN
    if (! windowsSessionEffectsAttach(handoff.effects_mapping))
        return 1;
    if (handoff.completion_event != 0)
    {
        completion_event = (HANDLE) handoff.completion_event;
        if (! waterwallCapabilityValidate(completion_event, L"Event", EVENT_MODIFY_STATE) ||
            ! SetHandleInformation(completion_event, HANDLE_FLAG_INHERIT, 0) || atexit(waterwallOrderlyReturn) != 0)
            return 1;
    }
#endif

    waterwall_startup_options_t                startup_options = {0};
    const waterwall_startup_arguments_result_e arguments_result =
        waterwallStartupOptionsParse(argc, argv, &startup_options);
    if (arguments_result != kWaterwallStartupArgumentsRun)
    {
        waterwallStartupHandoffCleanup(&handoff);
        return arguments_result == kWaterwallStartupArgumentsExitSuccess ? 0 : 1;
    }

#ifdef OS_WIN
    if (startup_options.session_file != NULL || startup_options.recover_file != NULL ||
        startup_options.console_mode != 0)
    {
        fprintf(stderr, "Session and console options require the packed public executable\n");
        return 1;
    }
#endif

    if (startup_options.restricted_config)
    {
        configPolicyRestrict();
    }

    char  *core_file_content = NULL;
    size_t core_file_len     = 0;
    if (handoff.has_handoff)
    {
        if (handoff.orig_exe != NULL)
        {
            setOriginalExecutablePath(handoff.orig_exe);
        }
        if (handoff.source_name != NULL)
        {
            startup_options.core_json_input      = handoff.source_name;
            startup_options.core_json_from_stdin = (strcmp(handoff.source_name, "stdin") == 0);
        }
        if (waterwallStartupHandoffReceive(
                &handoff, startup_options.restricted_config, &core_file_content, &core_file_len) != 0)
        {
            waterwallStartupHandoffCleanup(&handoff);
            return 1;
        }
    }
    else
    {
        core_file_content = waterwallStartupOptionsReadCoreJson(&startup_options, &core_file_len);
        if (core_file_content == NULL)
        {
            waterwallStartupHandoffCleanup(&handoff);
            return 1;
        }
    }

    initWLibc();

    ww_startup_result_t  startup_result      = wwStartupSuccess();
    ww_startup_context_t core_settings_scope = {0};
    wwStartupContextBegin(&core_settings_scope);
    const bool core_settings_parsed = parseCoreSettings(core_file_content, core_file_len);
    startup_result                  = wwStartupContextEnd(&core_settings_scope);
    waterwallStartupOptionsFreeCoreJson(core_file_content);
    if (! core_settings_parsed)
    {
        waterwallStartupOptionsReportCoreJsonParseFailure(&startup_options);
        destroyCoreSettings();
        waterwallStartupHandoffCleanup(&handoff);
        return startup_result.exit_code != 0 ? startup_result.exit_code : 1;
    }
    waterwallStartupHandoffCleanup(&handoff);

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
        .application_finalizer = waterwallApplicationFinalize,
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
#ifdef OS_WIN
    if (startup_options.stop_event || startup_options.ready_event || startup_options.controller_process)
    {
        if (! waterwallLifecycleStart(
                startup_options.stop_event, startup_options.ready_event, startup_options.controller_process))
        {
            startup_result = wwStartupFailure(1);
            goto startup_failed;
        }
        tunWindowsDnsSetStartupStopEvent((HANDLE) waterwallLifecycleStopEvent());
        if (! waterwallStartupCheckpoint())
        {
            goto startup_failed;
        }
    }
#endif
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
#ifdef OS_WIN
    globalstateRunMainThreadWithStartupHooks(waterwallLifecycleCheckpoint, waterwallLifecyclePublishReady);
#else
    runMainThread();
#endif
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
