/*
 * Covers: json helpers; the explicit inputs, callbacks and expected results below define this suite.
 * Setup: The included implementation/API and the deterministic inputs shown below; no integration
 * topology is implied.
 * Cases: testJsonIntegerInRange
 * Checks: Assertion labels include: valid uint64 string was rejected; valid uint64 string produced the
 * wrong value; invalid uint64 string was accepted; rejected uint64 string modified the destination
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.json_helpers_unit
 */
#include "wwapi.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

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

static void testExactIntegers(void)
{
    static const char *const rejected[] = {"9223372036854775808",
                                           "9223372036854775808.0",
                                           "9.223372036854775808e18",
                                           "1.0",
                                           "1e3",
                                           "9007199254740993.0",
                                           "9007199254740993e0",
                                           "1e-1000",
                                           "-1",
                                           "0.5",
                                           "1e1000",
                                           "18446744073709551616"};
    for (size_t i = 0; i < ARRAY_SIZE(rejected); ++i)
    {
        cJSON *item = cJSON_Parse(rejected[i]);
        require(item != NULL && cJSON_IsNumber(item), "floating point JSON parsing stopped working");
        uint64_t value = 123;
        require(! getUint64FromJson(&value, item) && value == 123, "inexact input changed integer identity");
        cJSON *copy = cJSON_Duplicate(item, true);
        require(! getUint64FromJson(&value, copy) && value == 123, "duplication lost integer invalidity");
        cJSON_Delete(copy);
        cJSON_Delete(item);
    }
    const uint64_t values[] = {0,
                               9007199254740991ULL,
                               9007199254740992ULL,
                               9007199254740993ULL,
                               INT64_MAX,
                               (uint64_t) INT64_MAX + 1,
                               UINT64_MAX};
    for (size_t i = 0; i < ARRAY_SIZE(values); ++i)
    {
        cJSON *object = cJSON_CreateObject();
        require(jsonAddUint64ToObject(object, "id", values[i]), "integer creation failed");
        char    *wire   = cJSON_PrintUnformatted(object);
        cJSON   *parsed = cJSON_Parse(wire);
        uint64_t value  = 123;
        require(getUint64FromJson(&value, cJSON_GetObjectItemCaseSensitive(parsed, "id")) && value == values[i],
                "supported counter failed exact export/parse/import");
        cJSON_Delete(parsed);
        cJSON_free(wire);
        cJSON_Delete(object);
    }
    cJSON   *item  = cJSON_Parse("9223372036854775807");
    uint64_t value = 0;
    require(getUint64FromJson(&value, item) && value == INT64_MAX, "INT64_MAX token was rounded");
    cJSON_SetNumberValue(item, 9223372036854775808.0);
    require(! getUint64FromJson(&value, item) && value == INT64_MAX, "setter retained stale validity on overflow");
    cJSON_SetNumberValue(item, NAN);
    require(! getUint64FromJson(&value, item), "NaN became an integer");
    cJSON_SetNumberValue(item, 1.5);
    require(! getUint64FromJson(&value, item), "fraction became an integer");
    cJSON_SetNumberValue(item, 42);
    require(getUint64FromJson(&value, item) && value == 42, "exact double setter failed");
    cJSON_SetIntValue(item, INT64_MAX);
    cJSON *copy = cJSON_Duplicate(item, true);
    require(getUint64FromJson(&value, copy) && value == INT64_MAX, "duplicate lost exact INT64_MAX");
    cJSON_Delete(copy);
    cJSON_SetIntValue(item, 9007199254740993LL);
    item->valueint = 9007199254740992LL; /* same double; provenance must still disagree */
    require(! getUint64FromJson(&value, item), "direct mutation retained stale integer provenance");
    cJSON_Delete(item);
    item = cJSON_Parse("\"18446744073709551615\"");
    require(getUint64FromJson(&value, item) && value == UINT64_MAX, "UINT64_MAX string was rounded");
    cJSON_Delete(item);
}

int main(void)
{
    testCaseSet("json_helpers_test");
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
    testExactIntegers();
    return 0;
}
