#include "bgp4_server.h"
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
    bool             open_received;
    bool             first_sent;

} bgp4_client_con_state_t;

static void upStream(tunnel_t *self, context_t *c)
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
                LOGE("Bgp4Server: message too short");
                goto disconnect;
            }

            if (bufferStreamLen(cstate->read_stream) >= ((unsigned int) kBgpHeaderLen + required_length))
            {
                shift_buffer_t *buf = bufferStreamRead(cstate->read_stream, kBgpHeaderLen + required_length);

                static const uint8_t kExpecetd[kMarkerLength] = {VAL_8X, VAL_8X};

                if (0 != memcmp(rawBuf(buf), kExpecetd, kMarkerLength))
                {
                    LOGE("Bgp4Server: invalid marker");
                    reuseBuffer(getContextBufferPool(c), buf);
                    goto disconnect;
                }
                shiftr(buf, kBgpHeaderLen);

                if (! cstate->open_received)
                {
                    if (bufLen(buf) < kBgpOpenPacketHeaderSize + 1) // +1 for type
                    {
                        LOGE("Bgp4Server: open packet length is shorter than bgp header");
                        reuseBuffer(getContextBufferPool(c), buf);
                        goto disconnect;
                    }

                    uint8_t bgp_type;
                    readUI8(buf, &bgp_type);
                    if (bgp_type == 1)
                    {
                        cstate->open_received = true;
                    }
                    else
                    {
                        LOGE("Bgp4Server: first message type was not bgp_open");
                        reuseBuffer(getContextBufferPool(c), buf);
                        goto disconnect;
                    }

                    shiftr(buf, kBgpOpenPacketHeaderSize); // now at index addition

                    uint8_t bgp_additions;
                    readUI8(buf, &bgp_additions);

                    if (bgp_additions > 0 && bufLen(buf) - 1 < bgp_additions)
                    {
                        LOGE("Bgp4Server: open message had extensions more than the length");
                        reuseBuffer(getContextBufferPool(c), buf);
                        goto disconnect;
                    }
                    shiftr(buf, bgp_additions + 1); // pass addition count and items
                }
                else
                {
                    shiftr(buf, 1); // pass type
                }

                if (bufLen(buf) <= 0)
                {
                    LOGE("Bgp4Server: message had no payload");
                    reuseBuffer(getContextBufferPool(c), buf);
                    goto disconnect;
                }

                context_t *data_ctx = newContext(c->line);
                data_ctx->payload   = buf;
                if (! cstate->first_sent)
                {
                    cstate->first_sent = true;
                    c->first           = true;
                }
                self->up->upStream(self->up, data_ctx);
            }
            else
            {
                break;
            }
        }
        destroyContext(c);
        return;
    }

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

    self->up->upStream(self->up, c);
    return;

disconnect:
    destroyBufferStream(cstate->read_stream);
    wwmGlobalFree(cstate);
    CSTATE_DROP(c);
    self->up->upStream(self->up, newFinContextFrom(c));
    self->dw->downStream(self->dw, newFinContextFrom(c));
    destroyContext(c);
}

static void downStream(tunnel_t *self, context_t *c)
{

    if (c->payload != NULL)
    {
        uint8_t bgp_type = 2 + (fastRand() % kBgpTypes - 1);

        shiftl(c->payload, 1); // type
        writeUI8(c->payload, bgp_type);

        uint16_t blen = (uint16_t) bufLen(c->payload);
        shiftl(c->payload, 2); // length
        writeUI16(c->payload, blen);

        shiftl(c->payload, kMarkerLength);
        memset(rawBufMut(c->payload), kMarker, kMarkerLength);
    }
    else if (c->fin)
    {
        bgp4_client_con_state_t *cstate = CSTATE(c);
        destroyBufferStream(cstate->read_stream);
        wwmGlobalFree(cstate);
        CSTATE_DROP(c);
    }

    self->dw->downStream(self->dw, c);
}

tunnel_t *newBgp4Server(node_instance_context_t *instance_info)
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

api_result_t apiBgp4Server(tunnel_t *self, const char *msg)
{
    (void) (self);
    (void) (msg);
    return (api_result_t){0};
}

tunnel_t *destroyBgp4Server(tunnel_t *self)
{
    (void) (self);
    return NULL;
}
tunnel_metadata_t getMetadataBgp4Server(void)
{
    return (tunnel_metadata_t){.version = 0001, .flags = 0x0};
}
