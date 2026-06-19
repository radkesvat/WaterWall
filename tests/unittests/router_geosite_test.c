#include "Router/structure.h"
#include "modules/destination_domain/destination_domain.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static line_t *testLineCreate(void)
{
    line_t *line = memoryAllocate(sizeof(*line));
    require(line != NULL, "failed to allocate test line");
    memoryZero(line, sizeof(*line));
    line->alive = true;
    return line;
}

static void testLineDestroy(line_t *line)
{
    addresscontextReset(&line->routing_context.src_ctx);
    addresscontextReset(&line->routing_context.dest_ctx);
    memoryFree(line);
}

static cJSON *parseJsonObject(const char *text)
{
    cJSON *json = cJSON_Parse(text);
    require(json != NULL, "failed to parse test JSON");
    require(cJSON_IsObject(json), "test JSON is not an object");
    return json;
}

static cJSON *settingsWithPath(const char *path)
{
    cJSON *settings = cJSON_CreateObject();
    require(settings != NULL, "failed to allocate settings object");
    require(cJSON_AddStringToObject(settings, "geosite-db-path", path) != NULL, "failed to add geosite-db-path");
    return settings;
}

static router_rule_t parseDestinationDomainRule(const char *json_text)
{
    router_rule_t rule = {0};
    cJSON        *json = parseJsonObject(json_text);
    require(routerDestinationDomainParse(&rule, json, 0) == kRouterFieldPresent, "destination-domain parse failed");
    cJSON_Delete(json);
    return rule;
}

static router_tstate_t geositeStateWithRule(router_rule_t *rule)
{
    router_tstate_t ts = {0};
    ts.rules           = rule;
    ts.rules_count     = 1;
    return ts;
}

static void writeTestFile(const char *path, const char *text)
{
    require(writeFile(path, text, stringLength(text)), "failed to write geosite test file");
}

static void makeTestPath(char *out, size_t out_len, const char *suffix)
{
    int written = snprintf(out, out_len, "/tmp/waterwall_router_geosite_%ld_%s.json", (long) getpid(), suffix);
    require(written > 0 && (size_t) written < out_len, "failed to build test path");
}

static void setDestinationDomain(line_t *line, const char *domain)
{
    addresscontextReset(&line->routing_context.dest_ctx);
    addresscontextDomainSetByString(&line->routing_context.dest_ctx, domain);
}

static bool ruleMatchesDomain(router_tstate_t *ts, router_rule_t *rule, const char *domain)
{
    line_t *line = testLineCreate();
    setDestinationDomain(line, domain);

    router_match_ctx_t mctx = {
        .router_state = ts,
        .line         = line,
    };
    bool matched = routerDestinationDomainMatch(rule, &mctx);

    testLineDestroy(line);
    return matched;
}

typedef struct geosite_set_snapshot_s
{
    uint8_t  set_bytes[sizeof(router_geosite_domain_set_t)];
    uint8_t *meta_bytes;
    uint8_t *table_bytes;
    size_t   meta_size;
    size_t   table_size;
} geosite_set_snapshot_t;

typedef struct geosite_thread_probe_s
{
    const router_geosite_compiled_list_t *list;
    atomic_bool                          *start;
    atomic_uint                          *ready_count;
    bool                                  ok;
} geosite_thread_probe_t;

enum
{
    kGeositeThreadSafetyReaders    = 8,
    kGeositeThreadSafetyIterations = 50000
};

static void geositeSnapshotSet(const router_geosite_domain_set_t *set, geosite_set_snapshot_t *snapshot)
{
    memoryZero(snapshot, sizeof(*snapshot));
    memoryCopy(snapshot->set_bytes, set, sizeof(*set));

    require(set->bucket_count >= 0, "STC set bucket count is negative");
    if (set->bucket_count == 0)
    {
        return;
    }

    require(set->meta != NULL, "STC set has buckets without metadata");
    require(set->table != NULL, "STC set has buckets without table storage");

    snapshot->meta_size  = sizeof(*set->meta) * (size_t) set->bucket_count;
    snapshot->table_size = sizeof(*set->table) * (size_t) set->bucket_count;

    snapshot->meta_bytes = memoryAllocate(snapshot->meta_size);
    require(snapshot->meta_bytes != NULL, "failed to snapshot STC set metadata");
    memoryCopy(snapshot->meta_bytes, set->meta, snapshot->meta_size);

    snapshot->table_bytes = memoryAllocate(snapshot->table_size);
    require(snapshot->table_bytes != NULL, "failed to snapshot STC set table");
    memoryCopy(snapshot->table_bytes, set->table, snapshot->table_size);
}

static void geositeSnapshotDestroy(geosite_set_snapshot_t *snapshot)
{
    if (snapshot->meta_bytes != NULL)
    {
        memoryFree(snapshot->meta_bytes);
        snapshot->meta_bytes = NULL;
    }
    if (snapshot->table_bytes != NULL)
    {
        memoryFree(snapshot->table_bytes);
        snapshot->table_bytes = NULL;
    }
    snapshot->meta_size  = 0;
    snapshot->table_size = 0;
}

static bool geositeSnapshotStillMatches(const router_geosite_domain_set_t *set, const geosite_set_snapshot_t *snapshot)
{
    if (memoryCompare(snapshot->set_bytes, set, sizeof(*set)) != 0)
    {
        return false;
    }

    if (snapshot->meta_size > 0 && memoryCompare(snapshot->meta_bytes, set->meta, snapshot->meta_size) != 0)
    {
        return false;
    }

    if (snapshot->table_size > 0 && memoryCompare(snapshot->table_bytes, set->table, snapshot->table_size) != 0)
    {
        return false;
    }

    return true;
}

static void *geositeThreadSafetyReader(void *userdata)
{
    geosite_thread_probe_t *probe = userdata;

    atomic_fetch_add(probe->ready_count, 1U);
    while (! atomic_load(probe->start))
    {
    }

    probe->ok = true;
    for (uint32_t i = 0; i < kGeositeThreadSafetyIterations; ++i)
    {
        probe->ok =
            probe->ok && routerGeositeCompiledListMatches(probe->list, "www.azure.com", stringLength("www.azure.com"));
        probe->ok = probe->ok &&
                    routerGeositeCompiledListMatches(probe->list, "login.azure.com", stringLength("login.azure.com"));
        probe->ok = probe->ok && routerGeositeCompiledListMatches(
                                     probe->list, "asset-cdn.example", stringLength("asset-cdn.example"));
        probe->ok =
            probe->ok && ! routerGeositeCompiledListMatches(probe->list, "badazure.com", stringLength("badazure.com"));
    }

    return NULL;
}

static const char *validGeositeJson(void)
{
    return "{\"format\":\"waterwall-router-geosite-v1\",\"lists\":["
           "{\"name\":\"azure\",\"code\":null,\"file_path\":null,\"resource_hash\":null,\"domains\":["
           "{\"type\":\"domain\",\"value\":\"azure.com\",\"attributes\":[{\"key\":\"test\",\"type\":\"bool\","
           "\"value\":true}]},"
           "{\"type\":\"full\",\"value\":\"login.azure.com\",\"attributes\":[]},"
           "{\"type\":\"plain\",\"value\":\"cdn\",\"attributes\":[]},"
           "{\"type\":\"regex\",\"value\":\"^ignored\\\\.example$\",\"attributes\":[]}"
           "]},"
           "{\"name\":\"cn\",\"code\":null,\"file_path\":null,\"resource_hash\":null,\"domains\":["
           "{\"type\":\"domain\",\"value\":\"example.cn\",\"attributes\":[]}"
           "]}"
           "]}";
}

static void testNoGeositeRuleDoesNotRequirePath(void)
{
    router_tstate_t ts       = {0};
    cJSON          *settings = cJSON_CreateObject();
    require(settings != NULL, "failed to allocate empty settings object");

    require(routerGeositeOpenIfNeeded(&ts, settings), "geosite compiler required a path without geosite rules");
    require(ts.geosite_lists == NULL, "geosite lists were compiled without geosite rules");
    require(ts.geosite_lists_count == 0, "geosite list count changed without geosite rules");
    require(ts.geosite_db_path == NULL, "geosite DB path stored without geosite rules");

    cJSON_Delete(settings);
}

static void testGeositeRuleRequiresPath(void)
{
    router_rule_t   rule     = parseDestinationDomainRule("{\"destination-domain\":\"geosite:azure\"}");
    router_tstate_t ts       = geositeStateWithRule(&rule);
    cJSON          *settings = cJSON_CreateObject();
    require(settings != NULL, "failed to allocate empty settings object");

    require(routerRuleTableNeedsGeosite(&ts), "geosite rule was not detected");
    require(! routerGeositeOpenIfNeeded(&ts, settings), "geosite rule was accepted without geosite-db-path");
    require(ts.geosite_lists == NULL, "geosite lists leaked after missing path");
    require(ts.geosite_db_path == NULL, "geosite DB path leaked after missing path");

    routerDestinationDomainDestroy(&rule);
    cJSON_Delete(settings);
}

static void testMissingReferencedListFails(void)
{
    char path[256];
    makeTestPath(path, sizeof(path), "missing_list");
    writeTestFile(path, validGeositeJson());

    router_rule_t   rule     = parseDestinationDomainRule("{\"destination-domain\":\"geosite:missing\"}");
    router_tstate_t ts       = geositeStateWithRule(&rule);
    cJSON          *settings = settingsWithPath(path);

    require(! routerGeositeOpenIfNeeded(&ts, settings), "missing referenced geosite list was accepted");
    require(ts.geosite_lists == NULL, "compiled geosite lists leaked after missing list");
    require(ts.geosite_db_path == NULL, "geosite DB path leaked after missing list");

    routerDestinationDomainDestroy(&rule);
    cJSON_Delete(settings);
    remove(path);
}

static void testCompiledGeositeMatchesSupportedRuleTypes(void)
{
    char path[256];
    makeTestPath(path, sizeof(path), "valid");
    writeTestFile(path, validGeositeJson());

    router_rule_t   rule     = parseDestinationDomainRule("{\"destination-domain\":\"GeoSite:AZURE\"}");
    router_tstate_t ts       = geositeStateWithRule(&rule);
    cJSON          *settings = settingsWithPath(path);

    require(routerGeositeOpenIfNeeded(&ts, settings), "failed to compile valid geosite JSON");
    require(ts.geosite_lists != NULL, "valid geosite JSON did not produce compiled lists");
    require(ts.geosite_lists_count == 1, "duplicate or missing compiled geosite list");
    require(ts.geosite_db_path != NULL, "valid geosite JSON did not store the DB path");
    require(rule.destination_domain.geosite_lists_count == 1, "rule was not attached to compiled geosite list");

    require(ruleMatchesDomain(&ts, &rule, "login.azure.com"), "full geosite rule did not match exact host");
    require(ruleMatchesDomain(&ts, &rule, "www.azure.com"), "domain geosite rule did not match subdomain");
    require(ruleMatchesDomain(&ts, &rule, "AZURE.COM."), "geosite host normalization did not match root domain");
    require(ruleMatchesDomain(&ts, &rule, "asset-cdn.example"), "plain geosite rule did not match substring");
    require(! ruleMatchesDomain(&ts, &rule, "badazure.com"), "domain geosite rule matched a partial suffix");
    require(! ruleMatchesDomain(&ts, &rule, "ignored.example"), "skipped regex geosite rule matched unexpectedly");

    routerDestinationDomainDestroy(&rule);
    routerGeositeClose(&ts);
    require(ts.geosite_lists == NULL, "geosite close did not clear compiled lists");
    require(ts.geosite_lists_count == 0, "geosite close did not clear compiled list count");
    require(ts.geosite_db_path == NULL, "geosite close did not clear DB path");

    cJSON_Delete(settings);
    remove(path);
}

static void testMixedNormalAndGeositeOrSemantics(void)
{
    char path[256];
    makeTestPath(path, sizeof(path), "mixed");
    writeTestFile(path, validGeositeJson());

    router_rule_t rule =
        parseDestinationDomainRule("{\"destination-domain\":[\"plain.example.test\",\"geosite:azure\"]}");
    router_tstate_t ts       = geositeStateWithRule(&rule);
    cJSON          *settings = settingsWithPath(path);

    require(routerGeositeOpenIfNeeded(&ts, settings), "failed to compile mixed geosite rule");
    require(ruleMatchesDomain(&ts, &rule, "plain.example.test"), "normal destination-domain branch stopped matching");
    require(ruleMatchesDomain(&ts, &rule, "www.azure.com"), "geosite destination-domain branch did not match");
    require(! ruleMatchesDomain(&ts, &rule, "other.example.test"), "unmatched domain unexpectedly matched mixed rule");

    routerDestinationDomainDestroy(&rule);
    routerGeositeClose(&ts);
    cJSON_Delete(settings);
    remove(path);
}

static void testRepeatedListCompilesOnceAndAttachesBothRules(void)
{
    char path[256];
    makeTestPath(path, sizeof(path), "duplicate");
    writeTestFile(path, validGeositeJson());

    router_rule_t rules[2] = {
        parseDestinationDomainRule("{\"destination-domain\":\"geosite:azure\"}"),
        parseDestinationDomainRule("{\"destination-domain\":[\"geosite:AZURE\",\"geosite:azure\"]}"),
    };
    router_tstate_t ts = {
        .rules       = rules,
        .rules_count = 2,
    };
    cJSON *settings = settingsWithPath(path);

    require(routerGeositeOpenIfNeeded(&ts, settings), "failed to compile repeated geosite rules");
    require(ts.geosite_lists_count == 1, "same geosite list was compiled more than once");
    require(rules[0].destination_domain.geosite_lists_count == 1, "first rule did not get geosite handle");
    require(rules[1].destination_domain.geosite_lists_count == 1, "second rule did not deduplicate geosite handles");
    require(rules[0].destination_domain.geosite_lists[0] == rules[1].destination_domain.geosite_lists[0],
            "rules did not share the same compiled geosite handle");

    require(ruleMatchesDomain(&ts, &rules[0], "www.azure.com"), "first repeated geosite rule did not match");
    require(ruleMatchesDomain(&ts, &rules[1], "login.azure.com"), "second repeated geosite rule did not match");

    routerDestinationDomainDestroy(&rules[0]);
    routerDestinationDomainDestroy(&rules[1]);
    routerGeositeClose(&ts);
    cJSON_Delete(settings);
    remove(path);
}

static void testCompiledGeositeStcReadLookupsDoNotMutateSets(void)
{
    char path[256];
    makeTestPath(path, sizeof(path), "thread_safety");
    writeTestFile(path, validGeositeJson());

    router_rule_t   rule     = parseDestinationDomainRule("{\"destination-domain\":\"geosite:azure\"}");
    router_tstate_t ts       = geositeStateWithRule(&rule);
    cJSON          *settings = settingsWithPath(path);

    require(routerGeositeOpenIfNeeded(&ts, settings), "failed to compile geosite thread-safety rule");
    require(rule.destination_domain.geosite_lists_count == 1, "thread-safety rule did not get geosite handle");

    const router_geosite_compiled_list_t *list = rule.destination_domain.geosite_lists[0];

    geosite_set_snapshot_t full_before = {0};
    geosite_set_snapshot_t root_before = {0};
    geositeSnapshotSet(&list->full_domains, &full_before);
    geositeSnapshotSet(&list->root_domains, &root_before);

    pthread_t              threads[kGeositeThreadSafetyReaders];
    geosite_thread_probe_t probes[kGeositeThreadSafetyReaders];
    atomic_bool            start;
    atomic_uint            ready_count;
    atomic_init(&start, false);
    atomic_init(&ready_count, 0U);

    for (uint32_t i = 0; i < kGeositeThreadSafetyReaders; ++i)
    {
        probes[i] = (geosite_thread_probe_t) {
            .list        = list,
            .start       = &start,
            .ready_count = &ready_count,
            .ok          = false,
        };
        require(pthread_create(&threads[i], NULL, geositeThreadSafetyReader, &probes[i]) == 0,
                "failed to create geosite STC reader thread");
    }

    while (atomic_load(&ready_count) != kGeositeThreadSafetyReaders)
    {
    }
    atomic_store(&start, true);

    for (uint32_t i = 0; i < kGeositeThreadSafetyReaders; ++i)
    {
        require(pthread_join(threads[i], NULL) == 0, "failed to join geosite STC reader thread");
        require(probes[i].ok, "concurrent geosite STC reader returned an unexpected match result");
    }

    require(geositeSnapshotStillMatches(&list->full_domains, &full_before),
            "STC full-domain hash set mutated during read-only geosite lookups");
    require(geositeSnapshotStillMatches(&list->root_domains, &root_before),
            "STC root-domain hash set mutated during read-only geosite lookups");

    geositeSnapshotDestroy(&full_before);
    geositeSnapshotDestroy(&root_before);
    routerDestinationDomainDestroy(&rule);
    routerGeositeClose(&ts);
    cJSON_Delete(settings);
    remove(path);
}

static void testDomainlessDestinationDoesNotMatch(void)
{
    char path[256];
    makeTestPath(path, sizeof(path), "domainless");
    writeTestFile(path, validGeositeJson());

    router_rule_t   rule     = parseDestinationDomainRule("{\"destination-domain\":\"geosite:azure\"}");
    router_tstate_t ts       = geositeStateWithRule(&rule);
    cJSON          *settings = settingsWithPath(path);
    require(routerGeositeOpenIfNeeded(&ts, settings), "failed to compile geosite rule");

    line_t            *line = testLineCreate();
    router_match_ctx_t mctx = {
        .router_state = &ts,
        .line         = line,
    };
    require(! routerDestinationDomainMatch(&rule, &mctx), "domainless destination matched geosite rule");

    testLineDestroy(line);
    routerDestinationDomainDestroy(&rule);
    routerGeositeClose(&ts);
    cJSON_Delete(settings);
    remove(path);
}

static void testInvalidJsonFailsAndCleansState(void)
{
    char path[256];
    makeTestPath(path, sizeof(path), "invalid");

    const char *json =
        "{\"format\":\"waterwall-router-geosite-v1\",\"lists\":[{\"name\":\"broken\",\"domains\":[{\"type\":"
        "\"bogus\",\"value\":\"example.com\",\"attributes\":[]}]}]}";
    writeTestFile(path, json);

    router_rule_t   rule     = parseDestinationDomainRule("{\"destination-domain\":\"geosite:broken\"}");
    router_tstate_t ts       = geositeStateWithRule(&rule);
    cJSON          *settings = settingsWithPath(path);

    require(! routerGeositeOpenIfNeeded(&ts, settings), "invalid geosite JSON was accepted");
    require(ts.geosite_lists == NULL, "compiled geosite lists leaked after invalid JSON");
    require(ts.geosite_db_path == NULL, "geosite DB path leaked after invalid JSON");

    routerDestinationDomainDestroy(&rule);
    cJSON_Delete(settings);
    remove(path);
}

static void testEmptyGeositeTokenFails(void)
{
    char path[256];
    makeTestPath(path, sizeof(path), "empty_token");
    writeTestFile(path, validGeositeJson());

    router_rule_t   rule     = parseDestinationDomainRule("{\"destination-domain\":\"geosite:\"}");
    router_tstate_t ts       = geositeStateWithRule(&rule);
    cJSON          *settings = settingsWithPath(path);

    require(! routerGeositeOpenIfNeeded(&ts, settings), "empty geosite token was accepted");

    routerDestinationDomainDestroy(&rule);
    cJSON_Delete(settings);
    remove(path);
}

int main(void)
{
    testNoGeositeRuleDoesNotRequirePath();
    testGeositeRuleRequiresPath();
    testMissingReferencedListFails();
    testCompiledGeositeMatchesSupportedRuleTypes();
    testMixedNormalAndGeositeOrSemantics();
    testRepeatedListCompilesOnceAndAttachesBothRules();
    testCompiledGeositeStcReadLookupsDoNotMutateSets();
    testDomainlessDestinationDoesNotMatch();
    testInvalidJsonFailsAndCleansState();
    testEmptyGeositeTokenFails();

    return 0;
}
