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

static bool geositePatternListName(const char *pattern, const char **out_name)
{
    if (! stringStartsWithIgnoreCase(pattern, "geosite:"))
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

typedef struct geosite_regex_builder_s
{
    char    *data;
    uint32_t len;
    uint32_t cap;
} geosite_regex_builder_t;

enum
{
    kGeositeRegexMaxExpandedRepeat = UINT8_MAX
};

static void geositeRegexBuilderDestroy(geosite_regex_builder_t *builder)
{
    if (builder->data != NULL)
    {
        memoryFree(builder->data);
        builder->data = NULL;
    }
    builder->len = 0;
    builder->cap = 0;
}

static bool geositeRegexBuilderReserve(geosite_regex_builder_t *builder, uint32_t extra)
{
    if (extra > UINT32_MAX - builder->len - 1U)
    {
        LOGF("Router: normalized GeoSite regex is too large");
        return false;
    }

    uint32_t need = builder->len + extra + 1U;
    if (need <= builder->cap)
    {
        return true;
    }

    uint32_t cap = builder->cap == 0 ? 64U : builder->cap;
    while (cap < need)
    {
        if (cap > UINT32_MAX / 2U)
        {
            cap = need;
            break;
        }
        cap *= 2U;
    }

    char *data = builder->data == NULL ? memoryAllocate(cap) : memoryReAllocate(builder->data, cap);
    if (UNLIKELY(data == NULL))
    {
        LOGF("Router: failed to allocate normalized GeoSite regex");
        return false;
    }

    builder->data = data;
    builder->cap  = cap;
    return true;
}

static bool geositeRegexBuilderAppend(geosite_regex_builder_t *builder, const char *data, uint32_t len)
{
    if (! geositeRegexBuilderReserve(builder, len))
    {
        return false;
    }

    if (len > 0)
    {
        memoryCopy(builder->data + builder->len, data, len);
        builder->len += len;
    }
    builder->data[builder->len] = '\0';
    return true;
}

static bool geositeRegexBuilderAppendChar(geosite_regex_builder_t *builder, char c)
{
    return geositeRegexBuilderAppend(builder, &c, 1U);
}

static bool geositeRegexParseNumber(const char *pattern, uint32_t len, uint32_t *index, uint32_t *out)
{
    uint32_t i = *index;
    if (i >= len || pattern[i] < '0' || pattern[i] > '9')
    {
        return false;
    }

    uint32_t value = 0;
    while (i < len && pattern[i] >= '0' && pattern[i] <= '9')
    {
        uint32_t digit = (uint32_t) (pattern[i] - '0');
        if (value > (UINT32_MAX - digit) / 10U)
        {
            return false;
        }
        value = (value * 10U) + digit;
        ++i;
    }

    *index = i;
    *out   = value;
    return true;
}

static bool geositeRegexParseBoundedRepeat(const char *pattern, uint32_t len, uint32_t open_index,
                                           bool *out_is_repeat, uint32_t *out_end, uint32_t *out_min,
                                           uint32_t *out_max, bool *out_unbounded)
{
    *out_is_repeat = false;
    *out_unbounded = false;
    *out_min       = 0;
    *out_max       = 0;
    *out_end       = open_index + 1U;

    uint32_t i   = open_index + 1U;
    uint32_t min = 0;
    if (! geositeRegexParseNumber(pattern, len, &i, &min))
    {
        return true;
    }

    uint32_t max       = min;
    bool     unbounded = false;
    if (i < len && pattern[i] == ',')
    {
        ++i;
        if (i < len && pattern[i] == '}')
        {
            unbounded = true;
        }
        else if (! geositeRegexParseNumber(pattern, len, &i, &max))
        {
            return true;
        }
    }

    if (i >= len || pattern[i] != '}')
    {
        return true;
    }

    if (! unbounded && max < min)
    {
        LOGF("Router: GeoSite regex \"%s\" has a bounded repeat with max smaller than min", pattern);
        return false;
    }

    if (min > kGeositeRegexMaxExpandedRepeat || (! unbounded && max > kGeositeRegexMaxExpandedRepeat))
    {
        LOGF("Router: GeoSite regex \"%s\" has a bounded repeat larger than %u",
             pattern,
             (unsigned int) kGeositeRegexMaxExpandedRepeat);
        return false;
    }

    *out_is_repeat = true;
    *out_unbounded = unbounded;
    *out_min       = min;
    *out_max       = max;
    *out_end       = i + 1U;
    return true;
}

static bool geositeRegexAppendExpandedRepeat(geosite_regex_builder_t *builder, uint32_t atom_start, uint32_t min,
                                             uint32_t max, bool unbounded)
{
    if (atom_start >= builder->len)
    {
        LOGF("Router: GeoSite regex has a bounded repeat without a preceding atom");
        return false;
    }

    uint32_t atom_len = builder->len - atom_start;
    char    *atom     = memoryAllocate((size_t) atom_len + 1U);
    if (UNLIKELY(atom == NULL))
    {
        LOGF("Router: failed to allocate GeoSite regex repeat atom");
        return false;
    }

    memoryCopy(atom, builder->data + atom_start, atom_len);
    atom[atom_len]           = '\0';
    builder->len             = atom_start;
    builder->data[atom_start] = '\0';

    bool ok = true;
    for (uint32_t i = 0; ok && i < min; ++i)
    {
        ok = geositeRegexBuilderAppend(builder, atom, atom_len);
    }

    if (ok && unbounded)
    {
        ok = geositeRegexBuilderAppend(builder, atom, atom_len) && geositeRegexBuilderAppendChar(builder, '*');
    }
    else if (ok)
    {
        for (uint32_t i = min; ok && i < max; ++i)
        {
            ok = geositeRegexBuilderAppend(builder, atom, atom_len) && geositeRegexBuilderAppendChar(builder, '?');
        }
    }

    memoryFree(atom);
    return ok;
}

static bool geositeRegexCopyEscape(geosite_regex_builder_t *builder, const char *pattern, uint32_t len,
                                   uint32_t *index)
{
    uint32_t start = *index;
    uint32_t end   = start + 1U;
    if (end < len)
    {
        ++end;
        if ((pattern[start + 1U] == 'x' || pattern[start + 1U] == 'p' || pattern[start + 1U] == 'P') && end < len &&
            pattern[end] == '{')
        {
            ++end;
            while (end < len)
            {
                char c = pattern[end++];
                if (c == '}')
                {
                    break;
                }
            }
        }
    }

    if (! geositeRegexBuilderAppend(builder, pattern + start, end - start))
    {
        return false;
    }

    *index = end;
    return true;
}

static bool geositeRegexCopyCharClass(geosite_regex_builder_t *builder, const char *pattern, uint32_t len,
                                      uint32_t *index)
{
    uint32_t start = *index;
    uint32_t end   = start + 1U;
    while (end < len)
    {
        if (pattern[end] == '\\' && end + 1U < len)
        {
            end += 2U;
            continue;
        }

        char c = pattern[end++];
        if (c == ']')
        {
            break;
        }
    }

    if (! geositeRegexBuilderAppend(builder, pattern + start, end - start))
    {
        return false;
    }

    *index = end;
    return true;
}

static bool geositeRegexNormalizeForStc(const char *pattern, char **out)
{
    *out = NULL;

    geosite_regex_builder_t builder = {0};
    uint32_t                len     = (uint32_t) stringLength(pattern);
    uint32_t                groups[CREG_MAX_CAPTURES] = {0};
    uint32_t                groups_count              = 0;
    uint32_t                atom_start                = 0;
    bool                    atom_ready                = false;

    for (uint32_t i = 0; i < len;)
    {
        char c = pattern[i];
        if (c == '\\')
        {
            atom_start = builder.len;
            atom_ready = true;
            if (! geositeRegexCopyEscape(&builder, pattern, len, &i))
            {
                geositeRegexBuilderDestroy(&builder);
                return false;
            }
            continue;
        }

        if (c == '[')
        {
            atom_start = builder.len;
            atom_ready = true;
            if (! geositeRegexCopyCharClass(&builder, pattern, len, &i))
            {
                geositeRegexBuilderDestroy(&builder);
                return false;
            }
            continue;
        }

        if (c == '(')
        {
            if (groups_count >= CREG_MAX_CAPTURES)
            {
                LOGF("Router: GeoSite regex \"%s\" has too many nested groups", pattern);
                geositeRegexBuilderDestroy(&builder);
                return false;
            }
            groups[groups_count++] = builder.len;
            atom_ready             = false;
            if (! geositeRegexBuilderAppendChar(&builder, c))
            {
                geositeRegexBuilderDestroy(&builder);
                return false;
            }
            ++i;
            continue;
        }

        if (c == ')')
        {
            atom_start = groups_count > 0 ? groups[--groups_count] : builder.len;
            atom_ready = true;
            if (! geositeRegexBuilderAppendChar(&builder, c))
            {
                geositeRegexBuilderDestroy(&builder);
                return false;
            }
            ++i;
            continue;
        }

        if (c == '{')
        {
            bool     is_repeat = false;
            bool     unbounded = false;
            uint32_t end       = 0;
            uint32_t min       = 0;
            uint32_t max       = 0;
            if (! geositeRegexParseBoundedRepeat(pattern, len, i, &is_repeat, &end, &min, &max, &unbounded))
            {
                geositeRegexBuilderDestroy(&builder);
                return false;
            }

            if (is_repeat)
            {
                if (! atom_ready || ! geositeRegexAppendExpandedRepeat(&builder, atom_start, min, max, unbounded))
                {
                    geositeRegexBuilderDestroy(&builder);
                    return false;
                }

                i          = end < len && pattern[end] == '?' ? end + 1U : end;
                atom_ready = false;
                continue;
            }
        }

        if (c == '|' || c == '^' || c == '$')
        {
            atom_ready = false;
        }
        else if (c != '*' && c != '+' && c != '?')
        {
            atom_start = builder.len;
            atom_ready = true;
        }

        if (! geositeRegexBuilderAppendChar(&builder, c))
        {
            geositeRegexBuilderDestroy(&builder);
            return false;
        }
        ++i;
    }

    if (builder.data == NULL && ! geositeRegexBuilderAppendChar(&builder, '\0'))
    {
        geositeRegexBuilderDestroy(&builder);
        return false;
    }

    *out = builder.data;
    return true;
}

static bool geositeCompiledListAddRegexRule(router_geosite_compiled_list_t *compiled,
                                            const geosite_domain_rule_t     *rule)
{
    char *pattern = NULL;
    if (! geositeRegexNormalizeForStc(rule->value, &pattern))
    {
        return false;
    }

    cregex *regex = &compiled->regex_patterns[compiled->regex_patterns_count];
    int     rc    = cregex_compile_pro(regex, pattern, CREG_ICASE);
    if (UNLIKELY(rc != CREG_OK))
    {
        LOGF("Router: GeoSite list \"%s\" has invalid regex \"%s\" (STC cregex error %d)",
             compiled->name,
             rule->value,
             rc);
        memoryFree(pattern);
        return false;
    }
    memoryFree(pattern);

    compiled->regex_patterns_count += 1U;
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

    if (compiled->regex_patterns != NULL)
    {
        for (uint32_t i = 0; i < compiled->regex_patterns_count; ++i)
        {
            if (compiled->regex_patterns[i].prog != NULL)
            {
                cregex_drop(&compiled->regex_patterns[i]);
            }
        }
        memoryFree(compiled->regex_patterns);
    }
    compiled->regex_patterns       = NULL;
    compiled->regex_patterns_count = 0;
}

static bool geositeCompiledListCompile(router_geosite_compiled_list_t *compiled, const geosite_list_t *list)
{
    compiled->name = stringDuplicate(list->name);
    if (UNLIKELY(compiled->name == NULL))
    {
        LOGF("Router: failed to allocate compiled GeoSite list name");
        return false;
    }

    uint32_t full_count  = 0;
    uint32_t root_count  = 0;
    uint32_t regex_count = 0;
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
        else if (list->domains[i].type == kGeositeDomainRegex)
        {
            ++regex_count;
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

    if (regex_count > 0)
    {
        compiled->regex_patterns = memoryAllocateZero(sizeof(*compiled->regex_patterns) * (size_t) regex_count);
        if (UNLIKELY(compiled->regex_patterns == NULL))
        {
            LOGF("Router: failed to allocate GeoSite regex matchers");
            return false;
        }
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
            if (! geositeCompiledListAddRegexRule(compiled, rule))
            {
                return false;
            }
            break;
        default:
            LOGF("Router: unsupported GeoSite domain type while compiling list \"%s\"", list->name);
            return false;
        }
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

static bool geositeRegexPatternsMatch(const router_geosite_compiled_list_t *list,
                                      const router_geosite_host_cache_t    *host)
{
    csview host_view = {
        .buf  = host->host,
        .size = (ptrdiff_t) host->host_len,
    };

    for (uint32_t i = 0; i < list->regex_patterns_count; ++i)
    {
        int rc = cregex_match_sv(&list->regex_patterns[i], host_view, NULL, CREG_DEFAULT);
        if (rc == CREG_OK)
        {
            return true;
        }
        if (UNLIKELY(rc != CREG_NOMATCH))
        {
            LOGF("Router: GeoSite regex matcher failed at runtime for list \"%s\" (STC cregex error %d)",
                 list->name,
                 rc);
            terminateProgram(1);
            return false;
        }
    }

    return false;
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

    if (geositeRegexPatternsMatch(list, host))
    {
        return true;
    }

    return false;
}

bool routerGeositeCompiledListMatches(const router_geosite_compiled_list_t *list, const char *host, uint32_t host_len)
{
    router_geosite_host_cache_t cache = {0};
    routerGeositeHostCachePrepare(&cache, (const uint8_t *) host, host_len);
    return routerGeositeCompiledListMatchesPrepared(list, &cache);
}

bool routerRuleTableNeedsGeosite(const router_tstate_t *ts)
{
    for (uint32_t i = 0; i < ts->rules_count; ++i)
    {
        const router_rule_t *rule = &ts->rules[i];
        if (! rule->destination_domain.present)
        {
            continue;
        }

        for (uint32_t j = 0; j < rule->destination_domain.patterns.count; ++j)
        {
            if (stringStartsWithIgnoreCase(rule->destination_domain.patterns.items[j], "geosite:"))
            {
                return true;
            }
        }
    }

    return false;
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
