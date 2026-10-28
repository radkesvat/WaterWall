#pragma once

#include "wwapi.h"

enum obfuscator_methods_e
{
    kObfuscatorMethodXor = kDvsFirstOption
};
enum obfuscator_skip_parts_e
{
    kObfuscatorSkipNone = kDvsFirstOption,
    kObfuscatorSkipIpv4,
    kObfuscatorSkipTransport
};
enum
{
    kObfuscatorTlsRecordHeaderSize    = 5,
    kObfuscatorMaxBufferedStreamBytes = 2U * 1024U * 1024U + UINT16_MAX + kObfuscatorTlsRecordHeaderSize
};
typedef enum
{
    kObfuscatorDecodeReady,
    kObfuscatorDecodeIncomplete,
    kObfuscatorDecodeInvalid,
    kObfuscatorDecodeOverflow
} obfuscator_decode_result_t;

/* Ordinary buffers only. No line access, I/O, callbacks, or lifecycle actions. */
void obfuscatorXorByte(uint8_t *data, size_t size, uint8_t key);
void obfuscatorApplyXor(sbuf_t *buf, uint32_t skip, uint8_t key);
/* Takes buf on every result. NULL means its body exceeds the record length limit. */
sbuf_t *obfuscatorWrapRecord(buffer_pool_t *pool, sbuf_t *buf);
/* Keeps ownership. Invalid records remain unmodified. */
bool obfuscatorStripRecord(sbuf_t *buf);
/* Takes buf on every result; NULL means aggregate allocation geometry was refused. */
sbuf_t *obfuscatorEncodeStream(buffer_pool_t *pool, sbuf_t *buf, uint32_t skip, uint8_t key);
/* Takes buf on every result; returns the sole owned decoded aggregate through out,
 * or NULL for incomplete/error input. The caller destroys stream on error.
 * Retains only incomplete wire data on successful return, before any caller dispatch. */
obfuscator_decode_result_t obfuscatorDecodeStream(buffer_pool_t *pool, buffer_stream_t *stream, sbuf_t *buf,
                                                  uint32_t skip, uint8_t key, sbuf_t **out);
