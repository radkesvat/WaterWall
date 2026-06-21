#include "game_udp_protocols.h"

bool junkdatagramsenderGameUdpProtocolsGenerate(sbuf_t *buf, const junkdatagramsender_module_args_t *args)
{
    return junkdatagramsenderGeneratePlaceholderPacket(buf, args, 8, 1200);
}
