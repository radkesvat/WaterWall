#include "protobuf_client.h"
#include <stdio.h>
#include <pb_encode.h>
#include <pb_decode.h>
#include "packet.pb.h"

tunnel_t *newProtoBufClient(node_instance_context_t *instance_info)
{
    // http2_client_state_t *state = malloc(sizeof(http2_client_state_t));
    // memset(state, 0, sizeof(http2_client_state_t));
    // cJSON *settings = instance_info->node_settings_json;

    // nghttp2_session_callbacks_new(&(state->cbs));
    // nghttp2_session_callbacks_set_on_header_callback(state->cbs, on_header_callback);
    // nghttp2_session_callbacks_set_on_data_chunk_recv_callback(state->cbs, on_data_chunk_recv_callback);
    // nghttp2_session_callbacks_set_on_frame_recv_callback(state->cbs, on_frame_recv_callback);

    // tunnel_t *t = newTunnel();
    // t->state = state;
    // t->upStream = &ProtoBufClientUpStream;
    // t->packetUpStream = &ProtoBufClientPacketUpStream;
    // t->downStream = &ProtoBufClientDownStream;
    // t->packetDownStream = &ProtoBufClientPacketDownStream;

    // atomic_thread_fence(memory_order_release);
    // return t;
}

api_result_t apiProtoBufClient(tunnel_t *self, char *msg)
{
    LOGE("protobuf-client API NOT IMPLEMENTED");
    return (api_result_t){0}; // TODO
}

tunnel_t *destroyProtoBufClient(tunnel_t *self)
{
    LOGE("http2-client DESTROY NOT IMPLEMENTED"); // TODO
    return NULL;
}

tunnel_metadata_t getMetadataProtoBufClient()
{
    return (tunnel_metadata_t){.version = 0001, .flags = 0x0};
}
