#include "config_policy.h"
#include "core_settings.h"
#include "startup.h"
#include "wlibc.h"
#include <stdio.h>
#include <string.h>

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

int main(void)
{
    initWLibc();

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
                             "{\"configs\":[\"nodes.json\"],\"misc\":{\"splice\":{}}}"};
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
