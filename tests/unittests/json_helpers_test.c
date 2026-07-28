#include "utils/json_helpers.h"

#include <math.h>

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static void requireParsed(const char *value, uint64_t expected)
{
    uint64_t parsed = 0;

    require(jsonParseUint64String(value, &parsed), "valid uint64 string was rejected");
    require(parsed == expected, "valid uint64 string produced the wrong value");
}

static void requireRejected(const char *value)
{
    uint64_t parsed = 123U;

    require(! jsonParseUint64String(value, &parsed), "invalid uint64 string was accepted");
    require(parsed == 123U, "rejected uint64 string modified the destination");
}

static void testJsonIntegerInRange(void)
{
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(obj, "minimum", 1);
    cJSON_AddNumberToObject(obj, "maximum", 65535);
    cJSON_AddNumberToObject(obj, "fraction", 8080.5);
    cJSON_AddNumberToObject(obj, "too_small", 0);
    cJSON_AddNumberToObject(obj, "too_large", 70000);
    cJSON_AddStringToObject(obj, "str", "8080");
    cJSON_AddBoolToObject(obj, "boolean", true);
    cJSON_AddNumberToObject(obj, "nan", NAN);
    cJSON_AddNumberToObject(obj, "positive_infinity", INFINITY);
    cJSON_AddNumberToObject(obj, "negative_infinity", -INFINITY);

    int64_t val = 99;

    json_value_status_t status = jsonGetObjectIntegerInRange(obj, "minimum", 1, 65535, &val);
    require(status == kJsonValuePresent, "inclusive minimum should be present");
    require(val == 1, "inclusive minimum produced the wrong value");

    val    = 99;
    status = jsonGetObjectIntegerInRange(obj, "maximum", 1, 65535, &val);
    require(status == kJsonValuePresent, "inclusive maximum should be present");
    require(val == 65535, "inclusive maximum produced the wrong value");

    val    = 99;
    status = jsonGetObjectIntegerInRange(obj, "fraction", 1, 65535, &val);
    require(status == kJsonValueInvalid, "fraction should be invalid");
    require(val == 99, "invalid status should not mutate value_out");

    val    = 99;
    status = jsonGetObjectIntegerInRange(obj, "too_small", 1, 65535, &val);
    require(status == kJsonValueInvalid, "below-minimum value should be invalid");
    require(val == 99, "below-minimum status should not mutate value_out");

    val    = 99;
    status = jsonGetObjectIntegerInRange(obj, "too_large", 1, 65535, &val);
    require(status == kJsonValueInvalid, "above-maximum value should be invalid");
    require(val == 99, "above-maximum status should not mutate value_out");

    val    = 99;
    status = jsonGetObjectIntegerInRange(obj, "str", 1, 65535, &val);
    require(status == kJsonValueInvalid, "string should be invalid");
    require(val == 99, "invalid status should not mutate value_out");

    val    = 99;
    status = jsonGetObjectIntegerInRange(obj, "boolean", 1, 65535, &val);
    require(status == kJsonValueInvalid, "boolean should be invalid");
    require(val == 99, "wrong-type status should not mutate value_out");

    static const char *const nonfinite_keys[] = {"nan", "positive_infinity", "negative_infinity"};
    for (size_t i = 0; i < ARRAY_SIZE(nonfinite_keys); ++i)
    {
        val    = 99;
        status = jsonGetObjectIntegerInRange(obj, nonfinite_keys[i], INT64_MIN, INT64_MAX, &val);
        require(status == kJsonValueInvalid, "non-finite number should be invalid");
        require(val == 99, "non-finite status should not mutate value_out");
    }

    val    = 99;
    status = jsonGetObjectIntegerInRange(obj, "nonexistent", 1, 65535, &val);
    require(status == kJsonValueMissing, "nonexistent key should be missing");
    require(val == 99, "missing status should not mutate value_out");

    require(jsonGetObjectIntegerInRange(NULL, "minimum", 1, 65535, &val) == kJsonValueMissing,
            "NULL object should report missing");
    require(jsonGetObjectIntegerInRange(obj, NULL, 1, 65535, &val) == kJsonValueMissing,
            "NULL key should report missing");

    cJSON *mismatched    = cJSON_CreateNumber(42);
    mismatched->valueint = 41;
    val                  = 99;
    require(! jsonGetIntegerInRange(mismatched, 1, 100, &val),
            "number inconsistent with its integer representation was accepted");
    require(val == 99, "representation mismatch modified value_out");
    require(! jsonGetIntegerInRange(mismatched, 1, 100, NULL), "NULL integer destination was accepted");
    cJSON_Delete(mismatched);

    cJSON_Delete(obj);
}

int main(void)
{
    requireParsed("0", 0U);
    requireParsed("42", 42U);
    requireParsed(" 42\t", 42U);
    requireParsed("18446744073709551615", UINT64_MAX);

    requireRejected(NULL);
    requireRejected("");
    requireRejected(" \t\r\n");
    requireRejected("-1");
    requireRejected(" -1");
    requireRejected("+1");
    requireRejected("1.0");
    requireRejected("0x10");
    requireRejected("--1");
    requireRejected("1x");
    requireRejected("1 2");
    requireRejected("18446744073709551616");

    testJsonIntegerInRange();
    return 0;
}
