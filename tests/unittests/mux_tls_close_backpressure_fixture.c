#include "mux_tls_close_backpressure_fixture.h"

void mxbRequire(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        fflush(stderr);
        exit(1);
    }
}

uint8_t mxbPatternByte(size_t index)
{
    return (uint8_t) (((index * 131U) + (index >> 7U) + 29U) & 0xffU);
}

void mxbSetupEnvironment(mxb_fixture_t *fixture, uint32_t combined_lstate_size)
{
    mxb_environment_t *env = &fixture->env;

    env->saved_flag_initialized = GSTATE.flag_initialized;
    env->saved_workers_count    = GSTATE.workers_count;
    env->saved_workers          = GSTATE.workers;
    env->saved_buffer_pools     = GSTATE.shortcut_buffer_pools;
    env->saved_wios_pools       = GSTATE.shortcut_wios_pools;
    env->saved_loops            = GSTATE.shortcut_loops;

    env->large_master = masterpoolCreateWithCapacity(2048);
    env->small_master = masterpoolCreateWithCapacity(64);
    env->wios_master  = masterpoolCreateWithCapacity(32);
    env->line_master  = masterpoolCreateWithCapacity(32);
    mxbRequire(env->large_master != NULL && env->small_master != NULL && env->wios_master != NULL &&
                   env->line_master != NULL,
               "failed to create Mux/TLS test master pools");

    env->pool = bufferpoolCreate(env->large_master, env->small_master, 32, 512 * 1024, 2048);
    mxbRequire(env->pool != NULL, "failed to create Mux/TLS test buffer pool");
    bufferpoolUpdateAllocationPaddings(env->pool, 64, 64);

    env->wios_pool = threadsafegenericpoolCreateWithDefaultAllocatorAndCapacity(env->wios_master, sizeof(wio_t), 16);
    mxbRequire(env->wios_pool != NULL, "failed to create Mux/TLS test wio pool");
    env->loop = wloopCreate(WLOOP_FLAG_AUTO_FREE, env->pool, 0);
    mxbRequire(env->loop != NULL, "failed to create Mux/TLS test event loop");

    env->line_pools[0] = genericpoolCreateWithDefaultCacheAlignedAllocatorAndCapacity(
        env->line_master, sizeof(line_t) + combined_lstate_size, 8);
    mxbRequire(env->line_pools[0] != NULL, "failed to create Mux/TLS test line pool");

    env->buffer_pools[0] = env->pool;
    env->wios_pools[0]   = env->wios_pool;
    env->loops[0]        = env->loop;
    env->worker          = (worker_t) {
                 .wid = 0, .buffer_pool = env->pool, .wios_pool = env->wios_pool, .loop = env->loop, .has_event_loop = true};

    GSTATE.flag_initialized      = true;
    GSTATE.workers_count         = 2;
    GSTATE.workers               = &env->worker;
    GSTATE.shortcut_buffer_pools = env->buffer_pools;
    GSTATE.shortcut_wios_pools   = env->wios_pools;
    GSTATE.shortcut_loops        = env->loops;
    testWorkerBindWID(0);

    fixture->decrypted_capacity = kMxbPlaintextLength;
    fixture->decrypted          = memoryAllocate(fixture->decrypted_capacity);
    mxbRequire(fixture->decrypted != NULL, "failed to allocate Mux/TLS plaintext capture");
}

void mxbTeardownEnvironment(mxb_fixture_t *fixture)
{
    mxb_environment_t *env = &fixture->env;

    mxbRequire(fixture->parent == NULL && fixture->child == NULL,
               "Mux/TLS fixture retained a line at environment teardown");

    memoryFree(fixture->decrypted);
    fixture->decrypted = NULL;
    genericpoolDestroy(env->line_pools[0]);
    wloopDestroy(&env->loop);
    threadsafegenericpoolDestroy(env->wios_pool);
    bufferpoolDestroy(env->pool);
    masterpoolMakeEmpty(env->large_master);
    masterpoolMakeEmpty(env->small_master);
    masterpoolMakeEmpty(env->wios_master);
    masterpoolDestroy(env->large_master);
    masterpoolDestroy(env->small_master);
    masterpoolDestroy(env->wios_master);
    masterpoolDestroy(env->line_master);

    testWorkerUnbindWID();
    GSTATE.flag_initialized      = env->saved_flag_initialized;
    GSTATE.workers_count         = env->saved_workers_count;
    GSTATE.workers               = env->saved_workers;
    GSTATE.shortcut_buffer_pools = env->saved_buffer_pools;
    GSTATE.shortcut_wios_pools   = env->saved_wios_pools;
    GSTATE.shortcut_loops        = env->saved_loops;
}

line_t *mxbCreateLine(mxb_fixture_t *fixture)
{
    line_t *line = lineCreateForWorker(0, fixture->env.line_pools, 0);
    mxbRequire(line != NULL, "failed to create a Mux/TLS test line");
    return line;
}

static void mxbWriteFrameHeader(uint8_t *out, uint32_t length, uint8_t flag, uint32_t cid)
{
    out[0] = (uint8_t) (length >> 8U);
    out[1] = (uint8_t) length;
    out[2] = flag;
    out[3] = 0;
    out[4] = (uint8_t) (cid >> 24U);
    out[5] = (uint8_t) (cid >> 16U);
    out[6] = (uint8_t) (cid >> 8U);
    out[7] = (uint8_t) cid;
}

sbuf_t *mxbMakeParentBatch(mxb_fixture_t *fixture, uint32_t cid, bool include_close)
{
    const uint32_t data_frames = (kMxbPlaintextLength + kMxbMuxDataLength - 1U) / kMxbMuxDataLength;
    const uint32_t frame_count = data_frames + (include_close ? 1U : 0U);
    const uint32_t batch_size  = kMxbPlaintextLength + (frame_count * kMxbMuxFrameLength);

    fixture->expected_mux_data_frames = data_frames;
    sbuf_t *batch                     = bufferpoolGetLargeBuffer(fixture->env.pool);
    batch                             = sbufReserveSpace(batch, batch_size);
    mxbRequire(batch != NULL, "failed to reserve the Mux/TLS parent batch");
    sbufSetLength(batch, batch_size);

    uint8_t *raw       = sbufGetMutablePtr(batch);
    uint32_t offset    = 0;
    size_t   plaintext = 0;
    for (uint32_t frame = 0; frame < data_frames; ++frame)
    {
        const uint32_t length = (uint32_t) min((size_t) kMxbMuxDataLength, kMxbPlaintextLength - plaintext);
        mxbWriteFrameHeader(raw + offset, length, kMxbMuxFlagData, cid);
        offset += kMxbMuxFrameLength;
        for (uint32_t i = 0; i < length; ++i)
        {
            raw[offset + i] = mxbPatternByte(plaintext + i);
        }
        offset += length;
        plaintext += length;
    }
    if (include_close)
    {
        mxbWriteFrameHeader(raw + offset, 0, kMxbMuxFlagClose, cid);
        offset += kMxbMuxFrameLength;
    }

    mxbRequire(offset == batch_size && plaintext == kMxbPlaintextLength,
               "Mux/TLS parent batch construction lost bytes");
    return batch;
}

bool mxbLineStateIsZero(const line_t *line, const tunnel_t *tunnel)
{
    const uint8_t *state = lineGetState((line_t *) (uintptr_t) line, (tunnel_t *) (uintptr_t) tunnel);
    for (uint32_t i = 0; i < tunnel->lstate_size; ++i)
    {
        if (state[i] != 0)
        {
            return false;
        }
    }
    return true;
}

void mxbRequirePlaintext(const mxb_fixture_t *fixture)
{
    mxbRequire(fixture->decrypted_length == kMxbPlaintextLength, "the TLS peer received the wrong plaintext length");
    for (size_t i = 0; i < fixture->decrypted_length; ++i)
    {
        if (fixture->decrypted[i] != mxbPatternByte(i))
        {
            mxbRequire(false, "the TLS peer received reordered or corrupted plaintext");
        }
    }
}
