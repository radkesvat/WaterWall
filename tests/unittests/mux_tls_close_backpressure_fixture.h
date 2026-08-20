#pragma once

#include "wwapi.h"

enum
{
    kMxbMuxFrameLength       = 8,
    kMxbMuxFlagOpen          = 0,
    kMxbMuxFlagClose         = 1,
    kMxbMuxFlagFlowPause     = 2,
    kMxbMuxFlagFlowResume    = 3,
    kMxbMuxFlagData          = 4,
    kMxbMuxDataLength        = 60 * 1024,
    kMxbPlaintextLength      = (9 * 1024 * 1024) + 123,
    kMxbMaximumDriveAttempts = 16,
};

typedef enum mxb_terminal_cause_e
{
    kMxbTerminalPeerClose,
    kMxbTerminalParentLoss,
} mxb_terminal_cause_t;

typedef struct mxb_environment_s
{
    uint8_t                     saved_flag_initialized;
    uint32_t                    saved_workers_count;
    worker_t                   *saved_workers;
    buffer_pool_t             **saved_buffer_pools;
    threadsafe_generic_pool_t **saved_wios_pools;
    wloop_t                   **saved_loops;

    master_pool_t             *large_master;
    master_pool_t             *small_master;
    master_pool_t             *wios_master;
    master_pool_t             *line_master;
    buffer_pool_t             *pool;
    threadsafe_generic_pool_t *wios_pool;
    wloop_t                   *loop;
    generic_pool_t            *line_pools[1];
    buffer_pool_t             *buffer_pools[1];
    threadsafe_generic_pool_t *wios_pools[1];
    wloop_t                   *loops[1];
    worker_t                   worker;
} mxb_environment_t;

typedef struct mxb_fixture_s
{
    mxb_environment_t env;
    tunnel_t         *mux;
    tunnel_t         *tls;
    tunnel_t         *wire;
    tunnel_t         *parent_peer;
    line_t           *parent;
    line_t           *child;
    void             *tls_private;

    uint8_t *decrypted;
    size_t   decrypted_length;
    size_t   decrypted_capacity;
    size_t   decrypted_at_finish;

    uint32_t expected_mux_data_frames;
    uint32_t tls_plaintext_calls;
    size_t   tls_plaintext_bytes;
    uint32_t wire_payload_calls;
    size_t   wire_payload_bytes;
    uint32_t wire_finish_calls;
    uint32_t child_owner_finish_calls;
    uint32_t parent_control_payloads;
    bool     child_owner_destroyed;
} mxb_fixture_t;

void    mxbRequire(bool condition, const char *message);
void    mxbSetupEnvironment(mxb_fixture_t *fixture, uint32_t combined_lstate_size);
void    mxbTeardownEnvironment(mxb_fixture_t *fixture);
line_t *mxbCreateLine(mxb_fixture_t *fixture);
sbuf_t *mxbMakeParentBatch(mxb_fixture_t *fixture, uint32_t cid, bool include_close);
bool    mxbLineStateIsZero(const line_t *line, const tunnel_t *tunnel);
void    mxbRequirePlaintext(const mxb_fixture_t *fixture);
uint8_t mxbPatternByte(size_t index);

void     mxbMuxClientCreate(mxb_fixture_t *fixture);
void     mxbMuxClientInitializeLines(mxb_fixture_t *fixture);
void     mxbMuxClientFeedParent(mxb_fixture_t *fixture, bool include_close);
void     mxbMuxClientFinishParent(mxb_fixture_t *fixture);
bool     mxbMuxClientChildIsPaused(const mxb_fixture_t *fixture);
bool     mxbMuxClientChildIsPeerDraining(const mxb_fixture_t *fixture);
bool     mxbMuxClientChildIsParentGoneDraining(const mxb_fixture_t *fixture);
bool     mxbMuxClientChildHasNoParent(const mxb_fixture_t *fixture);
size_t   mxbMuxClientChildQueuedBytes(const mxb_fixture_t *fixture);
size_t   mxbMuxClientParentQueuedBytes(const mxb_fixture_t *fixture);
uint32_t mxbMuxClientDetachedChildren(const mxb_fixture_t *fixture);
size_t   mxbMuxClientDetachedBytes(const mxb_fixture_t *fixture);
void     mxbMuxClientDestroy(mxb_fixture_t *fixture);

void     mxbMuxServerCreate(mxb_fixture_t *fixture);
void     mxbMuxServerInitializeLines(mxb_fixture_t *fixture);
void     mxbMuxServerFeedParent(mxb_fixture_t *fixture, bool include_close);
void     mxbMuxServerFinishParent(mxb_fixture_t *fixture);
bool     mxbMuxServerChildIsPaused(const mxb_fixture_t *fixture);
bool     mxbMuxServerChildIsPeerDraining(const mxb_fixture_t *fixture);
bool     mxbMuxServerChildIsParentGoneDraining(const mxb_fixture_t *fixture);
bool     mxbMuxServerChildHasNoParent(const mxb_fixture_t *fixture);
size_t   mxbMuxServerChildQueuedBytes(const mxb_fixture_t *fixture);
size_t   mxbMuxServerParentQueuedBytes(const mxb_fixture_t *fixture);
uint32_t mxbMuxServerDetachedChildren(const mxb_fixture_t *fixture);
size_t   mxbMuxServerDetachedBytes(const mxb_fixture_t *fixture);
bool     mxbMuxServerDetachedHeadIsChild(const mxb_fixture_t *fixture);
void     mxbMuxServerDestroy(mxb_fixture_t *fixture);

void   mxbTlsServerCreate(mxb_fixture_t *fixture);
void   mxbTlsServerInitializeLine(mxb_fixture_t *fixture);
void   mxbTlsServerPauseWire(mxb_fixture_t *fixture);
void   mxbTlsServerResumeWire(mxb_fixture_t *fixture);
bool   mxbTlsServerForceReadyOutput(mxb_fixture_t *fixture);
size_t mxbTlsServerShapedBytes(const mxb_fixture_t *fixture);
bool   mxbTlsServerProducerPaused(const mxb_fixture_t *fixture);
void   mxbTlsServerDestroy(mxb_fixture_t *fixture);

void   mxbTlsClientCreate(mxb_fixture_t *fixture);
void   mxbTlsClientInitializeLine(mxb_fixture_t *fixture);
void   mxbTlsClientPauseWire(mxb_fixture_t *fixture);
void   mxbTlsClientResumeWire(mxb_fixture_t *fixture);
bool   mxbTlsClientForceReadyOutput(mxb_fixture_t *fixture);
size_t mxbTlsClientShapedBytes(const mxb_fixture_t *fixture);
bool   mxbTlsClientProducerPaused(const mxb_fixture_t *fixture);
void   mxbTlsClientDestroy(mxb_fixture_t *fixture);
