#pragma once

#include "wwapi.h"

/*
 * Runtime representation for geosite data loaded from a generated JSON file.
 * domain-list-community is organized as named domain lists such as "cn",
 * "azure", and "category-ads-all".
 */

typedef enum geosite_domain_type_e
{
    kGeositeDomainPlain      = 0, // keyword/plain substring rule
    kGeositeDomainRegex      = 1, // regular expression rule
    kGeositeDomainRootDomain = 2, // domain: rule, root domain plus subdomains
    kGeositeDomainFull       = 3  // full: rule, exact domain
} geosite_domain_type_t;

typedef enum geosite_attr_value_type_e
{
    kGeositeAttrBool  = 0,
    kGeositeAttrInt64 = 1
} geosite_attr_value_type_t;

typedef struct geosite_attribute_s
{
    char                     *key;
    geosite_attr_value_type_t value_type;
    union {
        bool    bool_value;
        int64_t int64_value;
    } value;
} geosite_attribute_t;

typedef struct geosite_domain_rule_s
{
    geosite_domain_type_t type;
    char                 *value;

    geosite_attribute_t *attributes;
    uint32_t             attributes_count;
} geosite_domain_rule_t;

typedef struct geosite_list_s
{
    char *name;

    /*
     * Optional protobuf-compatible metadata fields. These may stay NULL when
     * generated directly from domain-list-community source files.
     */
    char    *code;
    char    *file_path;
    uint8_t *resource_hash;
    uint32_t resource_hash_len;

    geosite_domain_rule_t *domains;
    uint32_t               domains_count;
} geosite_list_t;

typedef struct geosite_db_s
{
    geosite_list_t *lists;
    uint32_t        lists_count;
} geosite_db_t;

static inline bool geositeStringEqualsIgnoreCase(const char *left, const char *right)
{
    if (left == NULL || right == NULL)
    {
        return false;
    }

    uint32_t i = 0;
    for (; left[i] != '\0' && right[i] != '\0'; ++i)
    {
        if (asciiLower((uint8_t) left[i]) != asciiLower((uint8_t) right[i]))
        {
            return false;
        }
    }

    return left[i] == '\0' && right[i] == '\0';
}

/*
 * This lookup used to be named geositeDbFindSite(country_code). That was
 * misleading because domain-list-community entries are named domain lists
 * such as "azure", "cn", and "category-ads-all", not only country/site data.
 */
static inline const geosite_list_t *geositeDbFindListByName(const geosite_db_t *db, const char *list_name)
{
    if (db == NULL || list_name == NULL)
    {
        return NULL;
    }

    for (uint32_t i = 0; i < db->lists_count; ++i)
    {
        if (geositeStringEqualsIgnoreCase(db->lists[i].name, list_name))
        {
            return &db->lists[i];
        }
    }

    return NULL;
}

static inline bool geositeDomainRuleHasBoolAttribute(const geosite_domain_rule_t *rule, const char *key,
                                                     bool wanted_value)
{
    if (rule == NULL || key == NULL)
    {
        return false;
    }

    for (uint32_t i = 0; i < rule->attributes_count; ++i)
    {
        const geosite_attribute_t *attr = &rule->attributes[i];
        if (attr->value_type == kGeositeAttrBool && geositeStringEqualsIgnoreCase(attr->key, key) &&
            attr->value.bool_value == wanted_value)
        {
            return true;
        }
    }

    return false;
}
