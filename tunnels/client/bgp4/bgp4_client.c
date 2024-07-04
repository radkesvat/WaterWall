#include "bgp4_client.h"
#include "buffer_stream.h"
#include "frand.h"
#include "loggers/network_logger.h"
#include "utils/jsonutils.h"

enum
{
    kMarker                  = 0xFF,
    kMarkerLength            = 16,
    kBgpHeaderLen            = kMarkerLength + 2, // 16 byte marker + 2 byte length
    kBgpTypes                = 5,
    kBgpTypeOpen             = 1,
    kBgpTypUpdate            = 2,
    kBgpTypeNotification     = 3,
    kBgpTypeKeepAlive        = 4,
    kBgpTypeRouteRefresh     = 5,
    kBgpOpenPacketHeaderSize = 10,
    kMaxEncryptLen           = 8 * 4
};

#define VAL_1X kMarker
#define VAL_2X VAL_1X, VAL_1X
#define VAL_4X VAL_2X, VAL_2X
#define VAL_8X VAL_4X, VAL_4X

// open packet simulate:
// Version (8bit) | My AS (16bit) | Hold Time (16bit) | BGP Identifier (32bit)
// Optional Parameters Length (8 bit?)
static const uint8_t kBgpOpenInitialData[kBgpOpenPacketHeaderSize] = {4, 0, 0, 0, 90};

typedef struct bgp4_client_state_s
{
    uint16_t as_number;
    uint32_t sim_ip;
    hash_t   hpassword;
    void    *_;
} bgp4_client_state_t;

typedef struct bgp4_client_con_state_s
{
    buffer_stream_t *read_stream;

} bgp4_client_con_state_t;

static void upStream(tunnel_t *self, context_t *c)
{
    bgp4_client_state_t *state = TSTATE(self);

    if (c->payload != NULL)
    {
        if (c->first)
        {
            uint32_t additions = 3 + fastRand() % 8;

            shiftl(c->payload, kBgpOpenPacketHeaderSize + additions);
            uint8_t *header = rawBufMut(c->payload);

            // initialize with defaults
            memcpy(header, kBgpOpenInitialData, sizeof(kBgpOpenInitialData));

            memcpy(header + 1, &state->as_number, sizeof(state->as_number));
            memcpy(header + 1 + 2 + 2, &state->sim_ip, sizeof(state->sim_ip));

            header[1 + 2 + 2 + 4] = additions;
            for (uint32_t i = 0; i < additions; i++)
            {
                header[1 + 2 + 2 + 4 + 1 + i] = fastRand() % 200;
            }
        }

        uint8_t bgp_type = c->first ? 1 : 2 + (fastRand() % kBgpTypes - 1);

        shiftl(c->payload, 1); // type
        writeUI8(c->payload, bgp_type);

        uint16_t blen = (uint16_t) bufLen(c->payload);
        shiftl(c->payload, 2); // length
        writeUI16(c->payload, blen);

        shiftl(c->payload, kMarkerLength);
        memset(rawBufMut(c->payload), kMarker, kMarkerLength);

        // todo (obfuscate) payload header should at least kMaxEncryptLen bytes be obsfucated
    }
    else
    {
        bgp4_client_con_state_t *cstate = CSTATE(c);

        if (c->init)
        {
            cstate        = wwmGlobalMalloc(sizeof(bgp4_client_con_state_t));
            *cstate       = (bgp4_client_con_state_t){.read_stream = newBufferStream(getContextBufferPool(c))};
            CSTATE_MUT(c) = cstate;
        }
        else if (c->fin)
        {
            destroyBufferStream(cstate->read_stream);
            wwmGlobalFree(cstate);
            CSTATE_DROP(c);
        }
    }
    self->up->upStream(self->up, c);
}

static void downStream(tunnel_t *self, context_t *c)
{
    bgp4_client_con_state_t *cstate = CSTATE(c);

    if (c->payload != NULL)
    {
        bufferStreamPushContextPayload(cstate->read_stream, c);
        while (isAlive(c->line) && bufferStreamLen(cstate->read_stream) > kBgpHeaderLen)
        {
            uint16_t required_length = 0;
            bufferStreamViewBytesAt(cstate->read_stream, kMarkerLength, (uint8_t *) &required_length,
                                    sizeof(required_length));

            if (required_length <= 1)
            {
                LOGE("Bgp4Client: message  too short");
                goto disconnect;
            }

            if (bufferStreamLen(cstate->read_stream) >= ((unsigned int) kBgpHeaderLen + required_length))
            {
                shift_buffer_t *buf = bufferStreamRead(cstate->read_stream, kBgpHeaderLen + required_length);

                static const uint8_t kExpecetd[kMarkerLength] = {VAL_8X, VAL_8X};

                if (0 != memcmp(rawBuf(buf), kExpecetd, kMarkerLength))
                {
                    LOGE("Bgp4Client: invalid marker");
                    destroyBufferStream(cstate->read_stream);
                    reuseBuffer(getContextBufferPool(c), buf);
                    wwmGlobalFree(cstate);
                    CSTATE_DROP(c);
                    self->up->upStream(self->up, newFinContextFrom(c));
                    self->dw->downStream(self->dw, newFinContextFrom(c));
                    destroyContext(c);
                    return;
                }
                shiftr(buf, kBgpHeaderLen + 1); // 1 byte is type

                if (bufLen(buf) <= 0)
                {
                    LOGE("Bgp4Client: message had no payload");
                    reuseBuffer(getContextBufferPool(c), buf);
                    goto disconnect;
                }
                context_t *data_ctx = newContext(c->line);
                data_ctx->payload   = buf;
                self->dw->downStream(self->dw, data_ctx);
            }
            else
            {
                break;
            }
        }
        destroyContext(c);
        return;
    }

    if (c->fin)
    {
        destroyBufferStream(cstate->read_stream);
        wwmGlobalFree(cstate);
        CSTATE_DROP(c);
    }

    self->dw->downStream(self->dw, c);
    return;

disconnect:
    destroyBufferStream(cstate->read_stream);
    wwmGlobalFree(cstate);
    CSTATE_DROP(c);
    self->up->upStream(self->up, newFinContextFrom(c));
    self->dw->downStream(self->dw, newFinContextFrom(c));
    destroyContext(c);
}

tunnel_t *newBgp4Client(node_instance_context_t *instance_info)
{

    bgp4_client_state_t *state = wwmGlobalMalloc(sizeof(bgp4_client_state_t));
    memset(state, 0, sizeof(bgp4_client_state_t));

    const cJSON *settings = instance_info->node_settings_json;
    char        *buf      = NULL;
    getStringFromJsonObjectOrDefault(&buf, settings, "password", "passwd");
    state->hpassword = CALC_HASH_BYTES(buf, strlen(buf));
    wwmGlobalFree(buf);

    // todo (random data) its better to fill these with real data
    state->as_number = (uint16_t) fastRand();
    state->sim_ip    = (fastRand() * 3);

    tunnel_t *t   = newTunnel();
    t->state      = state;
    t->upStream   = &upStream;
    t->downStream = &downStream;

    return t;
}

api_result_t apiBgp4Client(tunnel_t *self, const char *msg)
{
    (void) (self);
    (void) (msg);
    return (api_result_t){0};
}

tunnel_t *destroyBgp4Client(tunnel_t *self)
{
    (void) (self);
    return NULL;
}
tunnel_metadata_t getMetadataBgp4Client(void)
{
    return (tunnel_metadata_t){.version = 0001, .flags = 0x0};
}
