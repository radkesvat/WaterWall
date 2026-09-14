#pragma once

#include "wwapi.h"

enum
{
    kHpsRequestLineLimit   = 8192,
    kHpsFieldLimit         = 128,
    kHpsChunkLineLimit     = 1024,
    kHpsTrailerLimit       = 16384,
    kHpsTrailerFields      = 64,
    kHpsInformationalLimit = 32
};

typedef struct hps_authority_s
{
    char      host[256];
    char      wire[264];
    ip_addr_t ip;
    uint16_t  port;
    bool      literal;
} hps_authority_t;

typedef enum hps_body_kind_e
{
    kHpsBodyDone,
    kHpsBodyFixed,
    kHpsBodyChunked,
    kHpsBodyEof
} hps_body_kind_t;

typedef struct hps_body_s
{
    hps_body_kind_t kind;
    uint64_t        remaining;
    unsigned        chunk_phase;
    unsigned        trailer_bytes;
    unsigned        trailer_fields;
    bool            reject_data;
} hps_body_t;

typedef struct hps_field_s
{
    char *name;
    char *value;
} hps_field_t;

/* Pointers borrow the caller's complete, NUL-terminated header block. */
typedef struct hps_header_s
{
    hps_field_t     fields[kHpsFieldLimit];
    unsigned        count;
    char           *method;
    char           *target;
    char           *reason;
    char           *credentials;
    hps_authority_t authority;
    hps_body_t      body;
    uint64_t        length;
    uint64_t        max_forwards;
    unsigned        status;
    bool            http10;
    bool            close;
    bool            connect;
    bool            head;
    bool            options;
    bool            local_options;
    bool            has_length;
    bool            chunked;
    bool            has_max_forwards;
} hps_header_t;

bool hpsAuthority(const char *text, size_t len, bool explicit_port, hps_authority_t *out);
bool hpsAuthorityEqual(const hps_authority_t *a, const hps_authority_t *b);
/* 0 means valid; otherwise an HTTP refusal status. */
unsigned hpsParseHeader(char *block, size_t len, bool response, bool response_to_head, hps_header_t *out);
bool hpsRewriteHeader(const hps_header_t *h, bool response, bool client_http10, bool close, char *out, size_t capacity,
                      size_t *length);
/* Consume one validated streaming slice; emit=false discards chunk framing for HTTP/1.0. */
int  hpsBodyStep(hps_body_t *body, const unsigned char *data, size_t len, bool decode, const hps_header_t *header,
                 size_t *consumed, bool *emit);
bool hpsDecodeBasic(const char *value, char username[256], char password[256], char key[512]);
