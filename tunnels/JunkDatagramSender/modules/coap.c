#include "coap.h"

bool junkdatagramsenderCoapGenerate(sbuf_t *buf, const junkdatagramsender_module_args_t *args)
{
    return junkdatagramsenderGeneratePlaceholderPacket(buf, args, 4, 1152);
}
