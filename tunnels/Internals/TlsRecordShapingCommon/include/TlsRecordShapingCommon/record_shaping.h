#pragma once

#include "wwapi.h"

enum
{
    kTlsRecordShapingMaxOutcomes           = 16,
    kTlsRecordShapingMaxApplicationRecords = 1024,
    kTlsRecordShapingMaxPaddingBytes       = 4096,
    kTlsRecordShapingMaxDelayMs            = 1000,
    kTlsRecordShapingRecordHeaderSize      = 5,
    kTlsRecordShapingMaxRecordBody         = 18432,
    kTlsRecordShapingQueueHardLimit        = 1024 * 1024,
    kTlsRecordShapingQueueHighWatermark    = 768 * 1024,
    kTlsRecordShapingQueueLowWatermark     = 384 * 1024,
    kTlsRecordShapingErrorSize             = 256,
};

typedef enum tlsrecordshaping_sender_role_e
{
    kTlsRecordShapingSenderClient,
    kTlsRecordShapingSenderServer,
} tlsrecordshaping_sender_role_t;

typedef struct tlsrecordshaping_range_s
{
    uint32_t minimum;
    uint32_t maximum;
} tlsrecordshaping_range_t;

typedef struct tlsrecordshaping_outcome_s
{
    tlsrecordshaping_range_t padding_bytes;
    tlsrecordshaping_range_t delay_ms;
    uint8_t                  probability;
    uint8_t                  delay_probability;
    bool                     has_padding;
    bool                     has_delay;
} tlsrecordshaping_outcome_t;

typedef struct tlsrecordshaping_config_s
{
    tlsrecordshaping_outcome_t     outcomes[kTlsRecordShapingMaxOutcomes];
    uint16_t                       first_application_records;
    uint8_t                        outcome_count;
    tlsrecordshaping_sender_role_t sender_role;
    bool                           enabled;
} tlsrecordshaping_config_t;

typedef struct tlsrecordshaping_state_s
{
    uint32_t application_records_seen;
    uint32_t records_padded;
    uint32_t records_delayed;
    uint64_t requested_padding_bytes;
    uint64_t effective_padding_bytes;
    size_t   maximum_queued_ciphertext_bytes;
} tlsrecordshaping_state_t;

typedef struct tlsrecordshaping_decision_s
{
    uint32_t requested_padding_bytes;
    uint32_t delay_ms;
    uint8_t  selected_outcome;
    bool     considered;
    bool     outcome_selected;
} tlsrecordshaping_decision_t;

typedef struct tlsrecordshaping_metadata_node_s tlsrecordshaping_metadata_node_t;
typedef struct tlsrecordshaping_output_node_s   tlsrecordshaping_output_node_t;

typedef struct tlsrecordshaping_output_queue_s
{
    buffer_stream_t                   ciphertext_stream;
    tlsrecordshaping_metadata_node_t *metadata_head;
    tlsrecordshaping_metadata_node_t *metadata_tail;
    tlsrecordshaping_metadata_node_t *pending_metadata_head;
    tlsrecordshaping_metadata_node_t *pending_metadata_tail;
    tlsrecordshaping_output_node_t   *output_head;
    tlsrecordshaping_output_node_t   *output_tail;
    size_t                            metadata_count;
    size_t                            pending_metadata_count;
    size_t                            output_count;
    size_t                            queued_ciphertext_bytes;
    uint64_t                          previous_release_at_ms;
    bool                              initialized;
} tlsrecordshaping_output_queue_t;

bool tlsrecordshapingParse(const cJSON *settings, tlsrecordshaping_sender_role_t sender_role,
                           tlsrecordshaping_config_t *config, char error[kTlsRecordShapingErrorSize]);

bool tlsrecordshapingSelectDeterministic(const tlsrecordshaping_config_t *config, tlsrecordshaping_state_t *state,
                                         uint32_t outcome_roll, uint32_t padding_draw, uint32_t delay_roll,
                                         uint32_t delay_draw, tlsrecordshaping_decision_t *decision);
bool tlsrecordshapingSample(const tlsrecordshaping_config_t *config, tlsrecordshaping_state_t *state,
                            tlsrecordshaping_decision_t *decision);
void tlsrecordshapingRecordEffectivePadding(tlsrecordshaping_state_t          *state,
                                            const tlsrecordshaping_decision_t *decision,
                                            uint32_t                           effective_padding_bytes);
const char *tlsrecordshapingConfigModeName(const tlsrecordshaping_config_t *config);
bool        tlsrecordshapingConfigCanDelay(const tlsrecordshaping_config_t *config);

void    tlsrecordshapingOutputQueueInitialize(tlsrecordshaping_output_queue_t *queue, buffer_pool_t *pool);
void    tlsrecordshapingOutputQueueDestroy(tlsrecordshaping_output_queue_t *queue);
bool    tlsrecordshapingOutputQueuePushMetadata(tlsrecordshaping_output_queue_t *queue, uint32_t delay_ms);
bool    tlsrecordshapingOutputQueuePushPendingMetadata(tlsrecordshaping_output_queue_t *queue, uint32_t delay_ms);
bool    tlsrecordshapingOutputQueueHasPendingMetadata(const tlsrecordshaping_output_queue_t *queue);
bool    tlsrecordshapingOutputQueueCommitMetadata(tlsrecordshaping_output_queue_t *queue, uint32_t fallback_delay_ms);
bool    tlsrecordshapingOutputQueueFeed(tlsrecordshaping_output_queue_t *queue, sbuf_t *ciphertext, uint64_t now_ms,
                                        char error[kTlsRecordShapingErrorSize]);
bool    tlsrecordshapingOutputQueueFinishFeed(const tlsrecordshaping_output_queue_t *queue,
                                              char                                   error[kTlsRecordShapingErrorSize]);
sbuf_t *tlsrecordshapingOutputQueuePopReady(tlsrecordshaping_output_queue_t *queue, uint64_t now_ms, bool force);
bool    tlsrecordshapingOutputQueueNextDelay(const tlsrecordshaping_output_queue_t *queue, uint64_t now_ms,
                                             uint32_t *delay_ms);
size_t  tlsrecordshapingOutputQueueBytes(const tlsrecordshaping_output_queue_t *queue);
size_t  tlsrecordshapingOutputQueueCount(const tlsrecordshaping_output_queue_t *queue);
bool    tlsrecordshapingOutputQueueIsEmpty(const tlsrecordshaping_output_queue_t *queue);
