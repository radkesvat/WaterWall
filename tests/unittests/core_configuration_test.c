#include "config_policy.h"
#include "core_settings.h"
#include "startup.h"
#include "startup_options.h"
#include "wlibc.h"
#include <stdio.h>
#include <string.h>

#ifdef OS_LINUX
int  __wrap_get_nprocs(void);
long __wrap_sysconf(int name);
long __real_sysconf(int name);

/* Model a machine with 16 configured logical CPUs, only three online. */
int __wrap_get_nprocs(void)
{
    return 3;
}

long __wrap_sysconf(int name)
{
    if (name == _SC_NPROCESSORS_CONF)
    {
        return 16;
    }
    return __real_sysconf(name);
}
#endif

#define CHECK(x)                                                                                                       \
    do                                                                                                                 \
    {                                                                                                                  \
        if (! (x))                                                                                                     \
        {                                                                                                              \
            fprintf(stderr, "check failed: %s:%d: %s\n", __FILE__, __LINE__, #x);                                      \
            return 1;                                                                                                  \
        }                                                                                                              \
    } while (0)

static bool testParse(const char *json)
{
    ww_startup_context_t ctx = {0};
    wwStartupContextBegin(&ctx);
    bool ok = parseCoreSettings(json, strlen(json));
    wwStartupContextEnd(&ctx);
    return ok;
}

static int testStartupOptions(void)
{
    char program[]       = "Waterwall";
    char verbose[]       = "--verbose";
    char config[]        = "--config:custom.json";
    char restricted[]    = "--restricted-config";
    char stdin_arg[]     = "--config:stdin";
    char version_arg[]   = "--version";
    char short_version[] = "-v";
    const struct
    {
        int         argc;
        char       *argv[5];
        bool        verbose;
        bool        restricted;
        const char *core_input;
    } cases[] = {
        {1, {program, NULL}, false, false, NULL},
        {2, {program, verbose, NULL}, true, false, NULL},
        {3, {program, verbose, config, NULL}, true, false, "custom.json"},
        {3, {program, config, verbose, NULL}, true, false, "custom.json"},
        {4, {program, verbose, restricted, stdin_arg, NULL}, true, true, "stdin"},
    };
    waterwall_startup_options_t options = {0};
    for (size_t i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        CHECK(waterwallStartupOptionsParse(cases[i].argc, cases[i].argv, &options) == kWaterwallStartupArgumentsRun);
        CHECK(options.verbose == cases[i].verbose && options.restricted_config == cases[i].restricted);
        if (cases[i].core_input != NULL)
        {
            CHECK(strcmp(options.core_json_input, cases[i].core_input) == 0);
            CHECK(options.core_json_from_stdin == (strcmp(cases[i].core_input, "stdin") == 0));
        }
    }
    CHECK(waterwallStartupOptionsParse(cases[0].argc, cases[0].argv, &options) == kWaterwallStartupArgumentsRun);
    CHECK(! options.verbose && ! options.restricted_config);

    char aliases[][sizeof("--debug-log")] = {
        "--verbose", "--log", "-log", "-verbose", "--showlog", "-showlog", "--debug-log"};
    for (size_t i = 0; i < ARRAY_SIZE(aliases); ++i)
    {
        char *arguments[] = {program, aliases[i], config, NULL};
        CHECK(waterwallStartupOptionsParse(3, arguments, &options) == kWaterwallStartupArgumentsRun);
        CHECK(options.verbose && strcmp(options.core_json_input, "custom.json") == 0);
        char *duplicate[] = {program, verbose, aliases[i], NULL};
        CHECK(waterwallStartupOptionsParse(3, duplicate, &options) == kWaterwallStartupArgumentsExitFailure);
        char *version_verbose[] = {program, version_arg, aliases[i], NULL};
        CHECK(waterwallStartupOptionsParse(3, version_verbose, &options) == kWaterwallStartupArgumentsExitFailure);
    }
    char *version[] = {program, short_version, NULL};
    CHECK(waterwallStartupOptionsParse(2, version, &options) == kWaterwallStartupArgumentsExitSuccess);
    return 0;
}

static int testVerboseLogging(void)
{
    const char *json = "{\"configs\":[\"nodes.json\"],\"misc\":{\"workers\":1},\"log\":{\"path\":\"logs/\","
                       "\"internal\":{\"loglevel\":\"SILENT\",\"console\":false,\"file\":\"\"},"
                       "\"core\":{\"loglevel\":\"WARN\",\"console\":false,\"file\":\"core.log\"},"
                       "\"network\":{\"loglevel\":\"ERROR\",\"console\":false,\"file\":\"network.log\"},"
                       "\"dns\":{\"loglevel\":\"DEBUG\",\"console\":false,\"file\":\"dns.log\"}}}";
    CHECK(testParse(json));
    struct core_settings_s *settings = getCoreSettings();
    CHECK(strcmp(settings->internal_log_level, "SILENT") == 0 && ! settings->internal_log_console);
    CHECK(strcmp(settings->core_log_level, "WARN") == 0 && ! settings->core_log_console);
    CHECK(strcmp(settings->network_log_level, "ERROR") == 0 && ! settings->network_log_console);
    CHECK(strcmp(settings->dns_log_level, "DEBUG") == 0 && ! settings->dns_log_console);

    enableCoreSettingsVerboseLogging();
    CHECK(strcmp(settings->internal_log_level, "VERBOSE") == 0 && settings->internal_log_console);
    CHECK(strcmp(settings->core_log_level, "VERBOSE") == 0 && settings->core_log_console);
    CHECK(strcmp(settings->network_log_level, "VERBOSE") == 0 && settings->network_log_console);
    CHECK(strcmp(settings->dns_log_level, "VERBOSE") == 0 && settings->dns_log_console);
    CHECK(strcmp(settings->internal_log_file_fullpath, "logs/") == 0);
    CHECK(strcmp(settings->core_log_file_fullpath, "logs/core.log") == 0);
    CHECK(strcmp(settings->network_log_file_fullpath, "logs/network.log") == 0);
    CHECK(strcmp(settings->dns_log_file_fullpath, "logs/dns.log") == 0);
    destroyCoreSettings();
    return 0;
}

int main(void)
{
    initWLibc();
    CHECK(testStartupOptions() == 0);
    CHECK(testVerboseLogging() == 0);

    const char *valid = "{\"configs\":[\"nodes.json\"],\"misc\":{\"workers\":2},"
                        "\"dns\":{\"domains\":[\"example.test\"],\"servers\":\"127.0.0.1\"}}";
    CHECK(testParse(valid));
    struct core_settings_s *settings = getCoreSettings();
    CHECK(settings != NULL && settings == getCoreSettings());
    CHECK(settings->workers_count == 2 && settings->mtu_size == 1500);
    CHECK(settings->splice_enabled);
    CHECK(settings->dns_options.timeout_ms == 1000);
    CHECK(settings->dns_options.ndomains == 1);
    CHECK(strcmp(settings->dns_options.domains[0], "example.test") == 0);
    CHECK(strcmp(settings->config_paths.data[0], "nodes.json") == 0);
    destroyCoreSettings();
    CHECK(getCoreSettings() == NULL);
    destroyCoreSettings();
#ifdef OS_LINUX
    const struct
    {
        const char  *json;
        unsigned int workers;
    } worker_cases[] = {
        {"{\"configs\":[\"nodes.json\"]}", 3},
        {"{\"configs\":[\"nodes.json\"],\"misc\":{}}", 3},
        {"{\"configs\":[\"nodes.json\"],\"misc\":{\"workers\":0}}", 3},
        {"{\"configs\":[\"nodes.json\"],\"misc\":{\"workers\":-1}}", 3},
        {"{\"configs\":[\"nodes.json\"],\"misc\":{\"workers\":5}}", 5},
        {"{\"configs\":[\"nodes.json\"],\"misc\":{\"workers\":300}}", 254},
    };
    for (size_t i = 0; i < sizeof(worker_cases) / sizeof(worker_cases[0]); ++i)
    {
        CHECK(testParse(worker_cases[i].json));
        CHECK(getCoreSettings()->workers_count == worker_cases[i].workers);
        destroyCoreSettings();
    }
#endif
    const struct
    {
        const char *json;
        bool        splice_enabled;
    } splice_cases[] = {
        {"{\"configs\":[\"nodes.json\"]}", true},
        {"{\"configs\":[\"nodes.json\"],\"misc\":{}}", true},
        {"{\"configs\":[\"nodes.json\"],\"misc\":{\"workers\":1}}", true},
        {"{\"configs\":[\"nodes.json\"],\"misc\":{\"splice\":true}}", true},
        {"{\"configs\":[\"nodes.json\"],\"misc\":{\"splice\":false}}", false},
    };
    for (size_t i = 0; i < sizeof(splice_cases) / sizeof(splice_cases[0]); ++i)
    {
        CHECK(testParse(splice_cases[i].json));
        CHECK(getCoreSettings()->splice_enabled == splice_cases[i].splice_enabled);
        destroyCoreSettings();
    }
#if defined(OS_LINUX) && ! defined(OS_ANDROID) && ! defined(OS_CYGWIN)
    const bool default_tcp_tune = true;
#else
    const bool default_tcp_tune = false;
#endif
    const struct
    {
        const char *json;
        bool        enabled;
    } tcp_tune_cases[] = {
        {"{\"configs\":[\"nodes.json\"]}", default_tcp_tune},
        {"{\"configs\":[\"nodes.json\"],\"misc\":{}}", default_tcp_tune},
        {"{\"configs\":[\"nodes.json\"],\"misc\":{\"workers\":1}}", default_tcp_tune},
        {"{\"configs\":[\"nodes.json\"],\"misc\":{\"splice\":false}}", default_tcp_tune},
        {"{\"configs\":[\"nodes.json\"],\"misc\":{\"tcp-tune\":true}}", true},
        {"{\"configs\":[\"nodes.json\"],\"misc\":{\"tcp-tune\":false}}", false},
    };
    for (size_t i = 0; i < ARRAY_SIZE(tcp_tune_cases); ++i)
    {
        CHECK(testParse(tcp_tune_cases[i].json));
        CHECK(getCoreSettings()->tcp_tune_enabled == tcp_tune_cases[i].enabled);
        destroyCoreSettings();
    }
    const char *invalid[] = {"{",
                             "{\"configs\":[]}",
                             "{\"configs\":[\"nodes.json\"],\"misc\":{\"workers\":4.5}}",
                             "{\"configs\":[\"nodes.json\"],\"dns\":{\"domains\":[\"ok\",1]}}",
                             "{\"configs\":[\"nodes.json\"],\"misc\":{\"mtu\":67}}",
                             "{\"configs\":[\"nodes.json\"],\"misc\":{\"splice\":null}}",
                             "{\"configs\":[\"nodes.json\"],\"misc\":{\"splice\":0}}",
                             "{\"configs\":[\"nodes.json\"],\"misc\":{\"splice\":1}}",
                             "{\"configs\":[\"nodes.json\"],\"misc\":{\"splice\":\"false\"}}",
                             "{\"configs\":[\"nodes.json\"],\"misc\":{\"splice\":[]}}",
                             "{\"configs\":[\"nodes.json\"],\"misc\":{\"splice\":{}}}",
                             "{\"configs\":[\"nodes.json\"],\"misc\":{\"tcp-tune\":null}}",
                             "{\"configs\":[\"nodes.json\"],\"misc\":{\"tcp-tune\":0}}",
                             "{\"configs\":[\"nodes.json\"],\"misc\":{\"tcp-tune\":1}}",
                             "{\"configs\":[\"nodes.json\"],\"misc\":{\"tcp-tune\":\"false\"}}",
                             "{\"configs\":[\"nodes.json\"],\"misc\":{\"tcp-tune\":[]}}",
                             "{\"configs\":[\"nodes.json\"],\"misc\":{\"tcp-tune\":{}}}"};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
    {
        CHECK(! testParse(invalid[i]));
        destroyCoreSettings();
        CHECK(getCoreSettings() == NULL);
    }
    CHECK(testParse(valid));
    destroyCoreSettings();
    configPolicyRestrict();
    const char           embedded_nul[] = "{}\0hidden";
    ww_startup_context_t ctx            = {0};
    wwStartupContextBegin(&ctx);
    CHECK(! parseCoreSettings(embedded_nul, sizeof(embedded_nul) - 1));
    wwStartupContextEnd(&ctx);
    destroyCoreSettings();
    return 0;
}
