#pragma once

#include "VmessCommon/crypto.h"

/* Borrowed input already admitted to the reader's budget. The caller owns the
 * queue, active head and its reservation, including any unconsumed suffix. */
typedef struct vmess_record_input_s
{
    buffer_queue_t              *pending;
    sbuf_t                     **head;
    buffer_budget_reservation_t *reservation;
} vmess_record_input_t;

typedef enum vmess_record_status_e
{
    kVmessRecordNeedMore,
    kVmessRecordPayload,
    kVmessRecordEof,
    kVmessRecordLengthError,
    kVmessRecordBodyError,
    kVmessRecordLimitError,
} vmess_record_status_t;

typedef struct vmess_record_result_s
{
    vmess_record_status_t status;
    sbuf_t               *payload;
    uint32_t              consumed;
} vmess_record_result_t;

/* Initialize at its final worker-owned address. Pool and budget outlive Destroy.
 * The reader owns only cached prefix bytes and one incomplete ordinary body;
 * source storage, cryptographic context, callbacks and line lifetime stay local
 * to the node. All logical bytes remain charged while moving between owners. */
typedef struct vmess_record_reader_s
{
    buffer_pool_t              *pool;
    buffer_budget_t            *budget;
    sbuf_t                     *body;
    buffer_budget_reservation_t body_reservation;
    uint32_t                    body_length;
    uint32_t                    body_filled;
    uint16_t                    prefix_filled;
    uint8_t                     prefix[18];
} vmess_record_reader_t;

void vmessRecordReaderInit(vmess_record_reader_t *reader, buffer_pool_t *pool, buffer_budget_t *budget);
/* Framed, ordinary input only. Advances the codec once per complete record.
 * consumed counts bytes removed from input by this call, even on NeedMore/error.
 * Payload transfers an uncharged ordinary buffer with full pool left padding.
 * EOF and all errors are terminal: destroy the reader before releasing its
 * budget. Destroy never touches the borrowed input or cryptographic context. */
vmess_record_result_t vmessRecordReaderRead(vmess_record_reader_t *reader, vmess_body_ctx_t *crypto,
                                            const vmess_record_input_t *input);
void                  vmessRecordReaderDestroy(vmess_record_reader_t *reader);
