#pragma once
#include "splice_buffer.h"
#include "wwapi.h"

typedef struct easy_fixture_s
{
    tunnel_t                *prev, *node, *next;
    tunnel_chain_t          *chain;
    line_t                  *line;
    unsigned                 upstream, downstream, finishes, established;
    bool                     close_on_payload;
    sbuf_t                  *expected;
    const void              *bytes;
    uint32_t                 length, prefix;
    bool                     splice;
    splice_buffer_metadata_t metadata;
} easy_fixture_t;

void    easyRequire(bool condition, const char *message);
void    easySetup(easy_fixture_t *f, tunnel_t *node);
void    easyTeardown(easy_fixture_t *f);
sbuf_t *easyPayload(bool splice);
void    easyExpect(easy_fixture_t *f, sbuf_t *buf, const void *bytes, uint32_t length, uint32_t prefix);
void    easyWatch(sbuf_t *buf);
void    easyRequireDisposed(void);
void    testHeaderSplice(bool splice);
void    testBridgeAndBlackHoleSplice(bool splice);
void    testUserControllerSplice(bool splice);
void    testJunkSplice(bool splice);
