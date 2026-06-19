#include "structure.h"

#include "loggers/network_logger.h"

static void geositeDomainRuleDestroy(geosite_domain_rule_t *rule)
{
    if (rule->value != NULL)
    {
        memoryFree(rule->value);
        rule->value = NULL;
    }

    for (uint32_t i = 0; i < rule->attributes_count; ++i)
    {
        if (rule->attributes[i].key != NULL)
        {
            memoryFree(rule->attributes[i].key);
            rule->attributes[i].key = NULL;
        }
    }

    if (rule->attributes != NULL)
    {
        memoryFree(rule->attributes);
        rule->attributes = NULL;
    }
    rule->attributes_count = 0;
}

static void geositeListDestroy(geosite_list_t *list)
{
    if (list->name != NULL)
    {
        memoryFree(list->name);
        list->name = NULL;
    }
    if (list->code != NULL)
    {
        memoryFree(list->code);
        list->code = NULL;
    }
    if (list->file_path != NULL)
    {
        memoryFree(list->file_path);
        list->file_path = NULL;
    }
    if (list->resource_hash != NULL)
    {
        memoryFree(list->resource_hash);
        list->resource_hash = NULL;
    }
    list->resource_hash_len = 0;

    for (uint32_t i = 0; i < list->domains_count; ++i)
    {
        geositeDomainRuleDestroy(&list->domains[i]);
    }

    if (list->domains != NULL)
    {
        memoryFree(list->domains);
        list->domains = NULL;
    }
    list->domains_count = 0;
}

static void geositeDbDestroy(geosite_db_t *db)
{
    if (db == NULL)
    {
        return;
    }

    for (uint32_t i = 0; i < db->lists_count; ++i)
    {
        geositeListDestroy(&db->lists[i]);
    }

    if (db->lists != NULL)
    {
        memoryFree(db->lists);
        db->lists = NULL;
    }
    db->lists_count = 0;

    memoryFree(db);
}

static bool geositeDuplicateRequiredString(const cJSON *object, const char *key, char **out, const char *path)
{
    const cJSON *value = cJSON_GetObjectItemCaseSensitive(object, key);
    if (! cJSON_IsString(value) || value->valuestring == NULL || value->valuestring[0] == '\0')
    {
        LOGF("Router: invalid GeoSite DB \"%s\": required string field \"%s\" is missing or empty", path, key);
        return false;
    }

    *out = stringDuplicate(value->valuestring);
    if (UNLIKELY(*out == NULL))
    {
        LOGF("Router: failed to allocate GeoSite string field \"%s\"", key);
        return false;
    }

    return true;
}

static bool geositeDuplicateOptionalString(const cJSON *object, const char *key, char **out, const char *path)
{
    const cJSON *value = cJSON_GetObjectItemCaseSensitive(object, key);
    if (value == NULL || cJSON_IsNull(value))
    {
        *out = NULL;
        return true;
    }

    if (! cJSON_IsString(value) || value->valuestring == NULL)
    {
        LOGF("Router: invalid GeoSite DB \"%s\": optional field \"%s\" must be a string or null", path, key);
        return false;
    }

    *out = stringDuplicate(value->valuestring);
    if (UNLIKELY(*out == NULL))
    {
        LOGF("Router: failed to allocate GeoSite string field \"%s\"", key);
        return false;
    }

    return true;
}

static bool geositeDuplicateOptionalBytes(const cJSON *object, const char *key, uint8_t **out, uint32_t *out_len,
                                          const char *path)
{
    const cJSON *value = cJSON_GetObjectItemCaseSensitive(object, key);
    if (value == NULL || cJSON_IsNull(value))
    {
        *out     = NULL;
        *out_len = 0;
        return true;
    }

    if (! cJSON_IsString(value) || value->valuestring == NULL)
    {
        LOGF("Router: invalid GeoSite DB \"%s\": optional field \"%s\" must be a string or null", path, key);
        return false;
    }

    uint32_t len = (uint32_t) stringLength(value->valuestring);
    if (len == 0)
    {
        *out     = NULL;
        *out_len = 0;
        return true;
    }

    *out = memoryAllocate(len);
    if (UNLIKELY(*out == NULL))
    {
        LOGF("Router: failed to allocate GeoSite byte field \"%s\"", key);
        return false;
    }

    memoryCopy(*out, value->valuestring, len);
    *out_len = len;
    return true;
}

static bool geositeDomainTypeParse(const char *text, geosite_domain_type_t *out)
{
    if (geositeStringEqualsIgnoreCase(text, "plain") || geositeStringEqualsIgnoreCase(text, "keyword"))
    {
        *out = kGeositeDomainPlain;
        return true;
    }
    if (geositeStringEqualsIgnoreCase(text, "regex") || geositeStringEqualsIgnoreCase(text, "regexp"))
    {
        *out = kGeositeDomainRegex;
        return true;
    }
    if (geositeStringEqualsIgnoreCase(text, "domain") || geositeStringEqualsIgnoreCase(text, "root_domain"))
    {
        *out = kGeositeDomainRootDomain;
        return true;
    }
    if (geositeStringEqualsIgnoreCase(text, "full"))
    {
        *out = kGeositeDomainFull;
        return true;
    }

    return false;
}

static bool geositeParseAttribute(geosite_attribute_t *attr, const cJSON *json, const char *path)
{
    if (! cJSON_IsObject(json))
    {
        LOGF("Router: invalid GeoSite DB \"%s\": attributes[] entries must be objects", path);
        return false;
    }

    if (! geositeDuplicateRequiredString(json, "key", &attr->key, path))
    {
        return false;
    }

    const cJSON *type = cJSON_GetObjectItemCaseSensitive(json, "type");
    if (! cJSON_IsString(type) || type->valuestring == NULL)
    {
        LOGF("Router: invalid GeoSite DB \"%s\": attribute \"type\" must be a string", path);
        return false;
    }

    const cJSON *value = cJSON_GetObjectItemCaseSensitive(json, "value");
    if (geositeStringEqualsIgnoreCase(type->valuestring, "bool"))
    {
        if (! cJSON_IsBool(value))
        {
            LOGF("Router: invalid GeoSite DB \"%s\": bool attribute \"value\" must be boolean", path);
            return false;
        }

        attr->value_type       = kGeositeAttrBool;
        attr->value.bool_value = cJSON_IsTrue(value);
        return true;
    }

    if (geositeStringEqualsIgnoreCase(type->valuestring, "int64"))
    {
        if (! cJSON_IsNumber(value) || value->valuedouble != (double) value->valueint)
        {
            LOGF("Router: invalid GeoSite DB \"%s\": int64 attribute \"value\" must be an integer", path);
            return false;
        }

        attr->value_type        = kGeositeAttrInt64;
        attr->value.int64_value = value->valueint;
        return true;
    }

    LOGF("Router: invalid GeoSite DB \"%s\": unsupported attribute type \"%s\"", path, type->valuestring);
    return false;
}

static bool geositeParseAttributes(geosite_domain_rule_t *rule, const cJSON *domain_json, const char *path)
{
    const cJSON *attributes = cJSON_GetObjectItemCaseSensitive(domain_json, "attributes");
    if (attributes == NULL || cJSON_IsNull(attributes))
    {
        return true;
    }

    if (! cJSON_IsArray(attributes))
    {
        LOGF("Router: invalid GeoSite DB \"%s\": domain \"attributes\" must be an array", path);
        return false;
    }

    int attributes_count = cJSON_GetArraySize(attributes);
    if (attributes_count == 0)
    {
        return true;
    }

    rule->attributes_count = (uint32_t) attributes_count;
    rule->attributes       = memoryAllocateZero(sizeof(*rule->attributes) * (size_t) rule->attributes_count);
    if (UNLIKELY(rule->attributes == NULL))
    {
        LOGF("Router: failed to allocate GeoSite attributes");
        return false;
    }

    uint32_t     index = 0;
    const cJSON *attr_json;
    cJSON_ArrayForEach(attr_json, attributes)
    {
        if (! geositeParseAttribute(&rule->attributes[index], attr_json, path))
        {
            return false;
        }
        ++index;
    }

    return true;
}

static bool geositeParseDomain(geosite_domain_rule_t *rule, const cJSON *json, const char *path)
{
    if (! cJSON_IsObject(json))
    {
        LOGF("Router: invalid GeoSite DB \"%s\": domains[] entries must be objects", path);
        return false;
    }

    const cJSON *type = cJSON_GetObjectItemCaseSensitive(json, "type");
    if (! cJSON_IsString(type) || type->valuestring == NULL || ! geositeDomainTypeParse(type->valuestring, &rule->type))
    {
        LOGF("Router: invalid GeoSite DB \"%s\": domain \"type\" must be one of plain, regex, domain, full", path);
        return false;
    }

    if (! geositeDuplicateRequiredString(json, "value", &rule->value, path))
    {
        return false;
    }

    return geositeParseAttributes(rule, json, path);
}

static bool geositeParseList(geosite_list_t *list, const cJSON *json, const char *path)
{
    if (! cJSON_IsObject(json))
    {
        LOGF("Router: invalid GeoSite DB \"%s\": lists[] entries must be objects", path);
        return false;
    }

    if (! geositeDuplicateRequiredString(json, "name", &list->name, path) ||
        ! geositeDuplicateOptionalString(json, "code", &list->code, path) ||
        ! geositeDuplicateOptionalString(json, "file_path", &list->file_path, path) ||
        ! geositeDuplicateOptionalBytes(json, "resource_hash", &list->resource_hash, &list->resource_hash_len, path))
    {
        return false;
    }

    const cJSON *domains = cJSON_GetObjectItemCaseSensitive(json, "domains");
    if (! cJSON_IsArray(domains))
    {
        LOGF("Router: invalid GeoSite DB \"%s\": list \"domains\" must be an array", path);
        return false;
    }

    int domains_count = cJSON_GetArraySize(domains);
    if (domains_count == 0)
    {
        return true;
    }

    list->domains_count = (uint32_t) domains_count;
    list->domains       = memoryAllocateZero(sizeof(*list->domains) * (size_t) list->domains_count);
    if (UNLIKELY(list->domains == NULL))
    {
        LOGF("Router: failed to allocate GeoSite domains");
        return false;
    }

    uint32_t     index = 0;
    const cJSON *domain_json;
    cJSON_ArrayForEach(domain_json, domains)
    {
        if (! geositeParseDomain(&list->domains[index], domain_json, path))
        {
            return false;
        }
        ++index;
    }

    return true;
}

static bool geositeDbParseJson(cJSON *root, geosite_db_t **out_db, const char *path)
{
    if (! cJSON_IsObject(root))
    {
        LOGF("Router: invalid GeoSite DB \"%s\": root must be an object", path);
        return false;
    }

    const cJSON *lists = cJSON_GetObjectItemCaseSensitive(root, "lists");
    if (! cJSON_IsArray(lists))
    {
        LOGF("Router: invalid GeoSite DB \"%s\": root \"lists\" must be an array", path);
        return false;
    }

    geosite_db_t *db = memoryAllocateZero(sizeof(*db));
    if (UNLIKELY(db == NULL))
    {
        LOGF("Router: failed to allocate GeoSite database");
        return false;
    }

    int lists_count = cJSON_GetArraySize(lists);
    if (lists_count > 0)
    {
        db->lists_count = (uint32_t) lists_count;
        db->lists       = memoryAllocateZero(sizeof(*db->lists) * (size_t) db->lists_count);
        if (UNLIKELY(db->lists == NULL))
        {
            LOGF("Router: failed to allocate GeoSite lists");
            geositeDbDestroy(db);
            return false;
        }
    }

    uint32_t     index = 0;
    const cJSON *list_json;
    cJSON_ArrayForEach(list_json, lists)
    {
        if (! geositeParseList(&db->lists[index], list_json, path))
        {
            geositeDbDestroy(db);
            return false;
        }
        ++index;
    }

    *out_db = db;
    return true;
}

static bool geositeDbLoadFromJsonFile(const char *path, geosite_db_t **out_db)
{
    *out_db = NULL;

    char *json_text = readFile(path);
    if (json_text == NULL)
    {
        LOGF("Router: failed to read GeoSite DB JSON \"%s\"", path);
        return false;
    }

    cJSON *root = cJSON_ParseWithLength(json_text, stringLength(json_text));
    memoryFree(json_text);

    if (root == NULL)
    {
        LOGF("Router: failed to parse GeoSite DB JSON \"%s\"", path);
        return false;
    }

    bool ok = geositeDbParseJson(root, out_db, path);
    cJSON_Delete(root);
    return ok;
}

static bool geositeHasPrefix(const char *text, const char *prefix)
{
    for (uint32_t i = 0; prefix[i] != '\0'; ++i)
    {
        if (asciiLower((uint8_t) text[i]) != (uint8_t) prefix[i])
        {
            return false;
        }
    }
    return true;
}

static bool geositePatternListName(const char *pattern, const char **out_name)
{
    if (! geositeHasPrefix(pattern, "geosite:"))
    {
        return false;
    }

    *out_name = pattern + sizeof("geosite:") - 1U;
    return true;
}

static bool geositeListNameAlreadyCollected(const char **names, uint32_t count, const char *name)
{
    for (uint32_t i = 0; i < count; ++i)
    {
        if (geositeStringEqualsIgnoreCase(names[i], name))
        {
            return true;
        }
    }
    return false;
}

static bool geositeCollectReferencedListNames(router_tstate_t *ts, const char ***out_names, uint32_t *out_count)
{
    *out_names = NULL;
    *out_count = 0;

    uint32_t tokens_count = 0;
    for (uint32_t i = 0; i < ts->rules_count; ++i)
    {
        router_match_destination_domain_t *condition = &ts->rules[i].destination_domain;
        if (! condition->present)
        {
            continue;
        }

        for (uint32_t j = 0; j < condition->patterns.count; ++j)
        {
            const char *name = NULL;
            if (geositePatternListName(condition->patterns.items[j], &name))
            {
                ++tokens_count;
            }
        }
    }

    if (tokens_count == 0)
    {
        return true;
    }

    const char **names = memoryAllocateZero(sizeof(*names) * (size_t) tokens_count);
    if (UNLIKELY(names == NULL))
    {
        LOGF("Router: failed to allocate GeoSite referenced list names");
        return false;
    }

    uint32_t names_count = 0;
    for (uint32_t i = 0; i < ts->rules_count; ++i)
    {
        router_match_destination_domain_t *condition = &ts->rules[i].destination_domain;
        if (! condition->present)
        {
            continue;
        }

        for (uint32_t j = 0; j < condition->patterns.count; ++j)
        {
            const char *name = NULL;
            if (! geositePatternListName(condition->patterns.items[j], &name))
            {
                continue;
            }

            if (name[0] == '\0')
            {
                LOGF("JSON Error: Router->settings->rules[]->destination-domain : geosite token requires a list name");
                memoryFree((void *) names);
                return false;
            }

            if (! geositeListNameAlreadyCollected(names, names_count, name))
            {
                names[names_count++] = name;
            }
        }
    }

    *out_names = names;
    *out_count = names_count;
    return true;
}

static bool geositeNormalizeDomainToOwned(const char *value, char **out, uint32_t *out_len)
{
    uint32_t len = (uint32_t) stringLength(value);
    while (len > 0 && value[len - 1U] == '.')
    {
        --len;
    }

    if (len == 0)
    {
        *out     = NULL;
        *out_len = 0;
        return true;
    }

    char *normalized = memoryAllocate((size_t) len + 1U);
    if (UNLIKELY(normalized == NULL))
    {
        LOGF("Router: failed to allocate normalized GeoSite domain");
        return false;
    }

    for (uint32_t i = 0; i < len; ++i)
    {
        normalized[i] = (char) asciiLower((uint8_t) value[i]);
    }
    normalized[len] = '\0';

    *out     = normalized;
    *out_len = len;
    return true;
}

bool routerGeositeNormalizeHost(const uint8_t *host, uint32_t host_len, char *out, uint32_t *out_len)
{
    if (host == NULL || host_len == 0 || host_len > UINT8_MAX)
    {
        *out_len = 0;
        return false;
    }

    while (host_len > 0 && host[host_len - 1U] == '.')
    {
        --host_len;
    }

    if (host_len == 0)
    {
        *out_len = 0;
        return false;
    }

    for (uint32_t i = 0; i < host_len; ++i)
    {
        out[i] = (char) asciiLower(host[i]);
    }
    out[host_len] = '\0';
    *out_len      = host_len;
    return true;
}

uint32_t routerGeositeBuildSuffixOffsets(const char *host, uint32_t host_len, uint8_t *offsets,
                                         uint32_t offsets_capacity)
{
    if (host == NULL || host_len == 0 || offsets == NULL || offsets_capacity == 0)
    {
        return 0;
    }

    uint32_t count = 1;
    offsets[0]     = 0;

    for (uint32_t i = 0; i < host_len && count < offsets_capacity; ++i)
    {
        if (host[i] == '.' && i + 1U < host_len)
        {
            offsets[count++] = (uint8_t) (i + 1U);
        }
    }

    return count;
}

void routerGeositeHostCachePrepare(router_geosite_host_cache_t *cache, const uint8_t *host, uint32_t host_len)
{
    cache->ready                = true;
    cache->valid                = false;
    cache->host[0]              = '\0';
    cache->host_len             = 0;
    cache->suffix_offsets_count = 0;

    if (! routerGeositeNormalizeHost(host, host_len, cache->host, &cache->host_len))
    {
        return;
    }

    cache->suffix_offsets_count =
        routerGeositeBuildSuffixOffsets(cache->host,
                                        cache->host_len,
                                        cache->suffix_offsets,
                                        (uint32_t) (sizeof(cache->suffix_offsets) / sizeof(cache->suffix_offsets[0])));
    cache->valid = cache->suffix_offsets_count > 0;
}

static bool geositeDomainSetInsertOwned(router_geosite_domain_set_t *set, char *value, uint32_t len)
{
    router_geosite_domain_key_t key = {
        .value = value,
        .len   = len,
        .hash  = routerGeositeHashBytes(value, len),
    };

    router_geosite_domain_set_t_result result = router_geosite_domain_set_t_insert(set, key);
    if (UNLIKELY(result.ref == NULL))
    {
        LOGF("Router: failed to insert GeoSite domain into hash set");
        return false;
    }

    return true;
}

static bool geositeCompiledListAddSetRule(router_geosite_domain_set_t *set, const geosite_domain_rule_t *rule)
{
    char    *normalized = NULL;
    uint32_t len        = 0;
    if (! geositeNormalizeDomainToOwned(rule->value, &normalized, &len))
    {
        return false;
    }

    if (len == 0)
    {
        return true;
    }

    return geositeDomainSetInsertOwned(set, normalized, len);
}

static bool geositeCompiledListAddPlainRule(router_geosite_compiled_list_t *compiled, const geosite_domain_rule_t *rule)
{
    char    *normalized = NULL;
    uint32_t len        = 0;
    if (! geositeNormalizeDomainToOwned(rule->value, &normalized, &len))
    {
        return false;
    }

    if (len == 0)
    {
        return true;
    }

    char **patterns = memoryReAllocate(
        compiled->plain_patterns, sizeof(*compiled->plain_patterns) * (size_t) (compiled->plain_patterns_count + 1U));
    if (UNLIKELY(patterns == NULL))
    {
        memoryFree(normalized);
        LOGF("Router: failed to allocate GeoSite plain matchers");
        return false;
    }

    compiled->plain_patterns                                 = patterns;
    compiled->plain_patterns[compiled->plain_patterns_count] = normalized;
    compiled->plain_patterns_count += 1U;
    return true;
}

static void geositeCompiledListDestroy(router_geosite_compiled_list_t *compiled)
{
    if (compiled->name != NULL)
    {
        memoryFree(compiled->name);
        compiled->name = NULL;
    }

    router_geosite_domain_set_t_drop(&compiled->full_domains);
    router_geosite_domain_set_t_drop(&compiled->root_domains);

    if (compiled->plain_patterns != NULL)
    {
        for (uint32_t i = 0; i < compiled->plain_patterns_count; ++i)
        {
            if (compiled->plain_patterns[i] != NULL)
            {
                memoryFree(compiled->plain_patterns[i]);
            }
        }
        memoryFree(compiled->plain_patterns);
    }

    compiled->plain_patterns       = NULL;
    compiled->plain_patterns_count = 0;
    compiled->skipped_regex_count  = 0;
}

static bool geositeCompiledListCompile(router_geosite_compiled_list_t *compiled, const geosite_list_t *list)
{
    compiled->name = stringDuplicate(list->name);
    if (UNLIKELY(compiled->name == NULL))
    {
        LOGF("Router: failed to allocate compiled GeoSite list name");
        return false;
    }

    uint32_t full_count = 0;
    uint32_t root_count = 0;
    for (uint32_t i = 0; i < list->domains_count; ++i)
    {
        if (list->domains[i].type == kGeositeDomainFull)
        {
            ++full_count;
        }
        else if (list->domains[i].type == kGeositeDomainRootDomain)
        {
            ++root_count;
        }
    }

    if (full_count > 0 && UNLIKELY(! router_geosite_domain_set_t_reserve(&compiled->full_domains, (isize) full_count)))
    {
        LOGF("Router: failed to reserve GeoSite full-domain hash set");
        return false;
    }

    if (root_count > 0 && UNLIKELY(! router_geosite_domain_set_t_reserve(&compiled->root_domains, (isize) root_count)))
    {
        LOGF("Router: failed to reserve GeoSite root-domain hash set");
        return false;
    }

    for (uint32_t i = 0; i < list->domains_count; ++i)
    {
        const geosite_domain_rule_t *rule = &list->domains[i];
        switch (rule->type)
        {
        case kGeositeDomainFull:
            if (! geositeCompiledListAddSetRule(&compiled->full_domains, rule))
            {
                return false;
            }
            break;
        case kGeositeDomainRootDomain:
            if (! geositeCompiledListAddSetRule(&compiled->root_domains, rule))
            {
                return false;
            }
            break;
        case kGeositeDomainPlain:
            if (! geositeCompiledListAddPlainRule(compiled, rule))
            {
                return false;
            }
            break;
        case kGeositeDomainRegex:
            ++compiled->skipped_regex_count;
            break;
        default:
            LOGF("Router: unsupported GeoSite domain type while compiling list \"%s\"", list->name);
            return false;
        }
    }

    if (compiled->skipped_regex_count > 0)
    {
        LOGW("Router: GeoSite list \"%s\" skipped %u regex rule(s); regex GeoSite matching is not supported yet",
             list->name,
             (unsigned int) compiled->skipped_regex_count);
    }

    return true;
}

static router_geosite_compiled_list_t *geositeFindCompiledList(router_tstate_t *ts, const char *name)
{
    for (uint32_t i = 0; i < ts->geosite_lists_count; ++i)
    {
        if (geositeStringEqualsIgnoreCase(ts->geosite_lists[i].name, name))
        {
            return &ts->geosite_lists[i];
        }
    }
    return NULL;
}

static bool geositeAttachCompiledList(router_match_destination_domain_t *condition,
                                      router_geosite_compiled_list_t    *compiled)
{
    for (uint32_t i = 0; i < condition->geosite_lists_count; ++i)
    {
        if (condition->geosite_lists[i] == compiled)
        {
            return true;
        }
    }

    router_geosite_compiled_list_t **lists = memoryReAllocate(
        condition->geosite_lists, sizeof(*condition->geosite_lists) * (size_t) (condition->geosite_lists_count + 1U));
    if (UNLIKELY(lists == NULL))
    {
        LOGF("Router: failed to allocate rule GeoSite handles");
        return false;
    }

    condition->geosite_lists                                 = lists;
    condition->geosite_lists[condition->geosite_lists_count] = compiled;
    condition->geosite_lists_count += 1U;
    return true;
}

static bool geositeAttachCompiledListsToRules(router_tstate_t *ts)
{
    for (uint32_t i = 0; i < ts->rules_count; ++i)
    {
        router_match_destination_domain_t *condition = &ts->rules[i].destination_domain;
        if (! condition->present)
        {
            continue;
        }

        for (uint32_t j = 0; j < condition->patterns.count; ++j)
        {
            const char *name = NULL;
            if (! geositePatternListName(condition->patterns.items[j], &name))
            {
                continue;
            }

            router_geosite_compiled_list_t *compiled = geositeFindCompiledList(ts, name);
            if (UNLIKELY(compiled == NULL))
            {
                LOGF("Router: internal error: compiled GeoSite list \"%s\" was not found", name);
                return false;
            }

            if (! geositeAttachCompiledList(condition, compiled))
            {
                return false;
            }
        }
    }

    return true;
}

static bool geositeCompileReferencedLists(router_tstate_t *ts, const geosite_db_t *db)
{
    const char **names       = NULL;
    uint32_t     names_count = 0;
    if (! geositeCollectReferencedListNames(ts, &names, &names_count))
    {
        return false;
    }

    if (names_count == 0)
    {
        return true;
    }

    ts->geosite_lists = memoryAllocateZero(sizeof(*ts->geosite_lists) * (size_t) names_count);
    if (UNLIKELY(ts->geosite_lists == NULL))
    {
        memoryFree((void *) names);
        LOGF("Router: failed to allocate compiled GeoSite lists");
        return false;
    }
    ts->geosite_lists_count = names_count;

    for (uint32_t i = 0; i < names_count; ++i)
    {
        const geosite_list_t *list = geositeDbFindListByName(db, names[i]);
        if (list == NULL)
        {
            LOGF("Router: GeoSite list \"%s\" was referenced by a rule but was not found in the configured DB",
                 names[i]);
            memoryFree((void *) names);
            return false;
        }

        if (! geositeCompiledListCompile(&ts->geosite_lists[i], list))
        {
            memoryFree((void *) names);
            return false;
        }
    }

    memoryFree((void *) names);
    return geositeAttachCompiledListsToRules(ts);
}

static bool geositePlainPatternMatches(const char *host, uint32_t host_len, const char *pattern)
{
    uint32_t pattern_len = (uint32_t) stringLength(pattern);
    if (pattern_len == 0 || pattern_len > host_len)
    {
        return false;
    }

    for (uint32_t i = 0; i <= host_len - pattern_len; ++i)
    {
        if (memoryCompare(host + i, pattern, pattern_len) == 0)
        {
            return true;
        }
    }
    return false;
}

static bool geositeDomainSetContains(const router_geosite_domain_set_t *set, const char *value, uint32_t len)
{
    /*
     * This is the runtime path used by worker threads. It intentionally relies
     * on STC hset contains() staying a const/read-only operation; the compiled
     * sets are built once during Router creation and are never mutated after
     * workers can classify lines.
     */
    router_geosite_domain_key_t key = {
        .value = value,
        .len   = len,
        .hash  = routerGeositeHashBytes(value, len),
    };
    return router_geosite_domain_set_t_contains(set, key);
}

bool routerGeositeCompiledListMatchesPrepared(const router_geosite_compiled_list_t *list,
                                              const router_geosite_host_cache_t    *host)
{
    if (list == NULL || host == NULL || ! host->valid)
    {
        return false;
    }

    if (geositeDomainSetContains(&list->full_domains, host->host, host->host_len))
    {
        return true;
    }

    for (uint32_t i = 0; i < host->suffix_offsets_count; ++i)
    {
        uint32_t suffix_start = host->suffix_offsets[i];
        if (suffix_start >= host->host_len)
        {
            continue;
        }

        if (geositeDomainSetContains(&list->root_domains, host->host + suffix_start, host->host_len - suffix_start))
        {
            return true;
        }
    }

    for (uint32_t i = 0; i < list->plain_patterns_count; ++i)
    {
        if (geositePlainPatternMatches(host->host, host->host_len, list->plain_patterns[i]))
        {
            return true;
        }
    }

    return false;
}

bool routerGeositeCompiledListMatches(const router_geosite_compiled_list_t *list, const char *host, uint32_t host_len)
{
    router_geosite_host_cache_t cache = {0};
    routerGeositeHostCachePrepare(&cache, (const uint8_t *) host, host_len);
    return routerGeositeCompiledListMatchesPrepared(list, &cache);
}

bool routerGeositeOpenIfNeeded(router_tstate_t *ts, const cJSON *settings)
{
    if (! routerRuleTableNeedsGeosite(ts))
    {
        return true;
    }

    if (ts->geosite_lists != NULL)
    {
        return true;
    }

    if (settings == NULL)
    {
        LOGF("JSON Error: Router->settings->geosite-db-path (string field) : required when geosite rules are used");
        return false;
    }

    const cJSON *path_json = cJSON_GetObjectItemCaseSensitive(settings, "geosite-db-path");
    if (! cJSON_IsString(path_json) || path_json->valuestring == NULL || path_json->valuestring[0] == '\0')
    {
        LOGF("JSON Error: Router->settings->geosite-db-path (string field) : required when geosite rules are used");
        return false;
    }

    ts->geosite_db_path = stringDuplicate(path_json->valuestring);
    if (UNLIKELY(ts->geosite_db_path == NULL))
    {
        LOGF("Router: failed to allocate geosite-db-path");
        return false;
    }

    geosite_db_t *db = NULL;
    if (! geositeDbLoadFromJsonFile(ts->geosite_db_path, &db))
    {
        routerGeositeClose(ts);
        return false;
    }

    bool ok = geositeCompileReferencedLists(ts, db);
    geositeDbDestroy(db);
    if (! ok)
    {
        routerGeositeClose(ts);
        return false;
    }

    return true;
}

void routerGeositeClose(router_tstate_t *ts)
{
    if (ts->geosite_lists != NULL)
    {
        for (uint32_t i = 0; i < ts->geosite_lists_count; ++i)
        {
            geositeCompiledListDestroy(&ts->geosite_lists[i]);
        }
        memoryFree(ts->geosite_lists);
        ts->geosite_lists = NULL;
    }
    ts->geosite_lists_count = 0;

    if (ts->geosite_db_path != NULL)
    {
        memoryFree(ts->geosite_db_path);
        ts->geosite_db_path = NULL;
    }
}
