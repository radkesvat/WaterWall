#pragma once

#include "wwapi.h"

/* Require an object containing only permitted, uniquely named fields. */
bool apiserverObjectKeysValid(const cJSON *object, const char *const *allowed, size_t count);

typedef struct api_request_s
{
    struct api_request_s *next;
    char                  id[65];
    char                  config[257];
    char                  node[257];
    char                  operation[65];
    char                  content_type[129];
    char                  client[257];
    uint8_t               token[32];
    uint8_t              *body;
    size_t                body_size;
    size_t                body_capacity;
    size_t                charge;
    size_t                wire_size;
    uint64_t              deadline_ms;
    const char           *error;
    bool                  close;
} api_request_t;

/* Caller reserves sizeof(request)+length+1 for owned values, plus length+8192
 * temporary parsing bytes. The lexical preflight limits depth and values first. */
void apiserverRequestParse(api_request_t *request, const char *bytes, size_t length);
/* Securely wipes owned body storage and the token, then resets the request.
 * The request allocation remains caller-owned. Valid after any parse result. */
void apiserverRequestClear(api_request_t *request);
bool apiserverTokenDecode(const char *text, uint8_t bytes[32]);
typedef enum api_response_measure_e
{
    kApiResponseValid,
    kApiResponseInvalid,
    kApiResponseTooLarge
} api_response_measure_t;

/* No allocation. Distinguish malformed UTF-8 handler text from size overflow. */
api_response_measure_t apiserverResponseMeasure(const char *id, const char *error,
                                                const node_api_operation_t *operation, enum api_result_e code,
                                                const uint8_t *body, size_t length, size_t *encoded_size);
/* Exact encoded length, excluding the prefix. SIZE_MAX refuses malformed or
 * unrepresentable output. error selects a fixed gateway body. */
size_t apiserverResponseSize(const char *id, const char *error, const node_api_operation_t *operation,
                             enum api_result_e code, const uint8_t *body, size_t length);
void   apiserverResponseWrite(char *dest, const char *id, const char *error, const node_api_operation_t *operation,
                              enum api_result_e code, const uint8_t *body, size_t length);
