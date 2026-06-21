#include "sip.h"

bool junkdatagramsenderSipGenerate(sbuf_t *buf, const junkdatagramsender_module_args_t *args)
{
    return junkdatagramsenderGeneratePlaceholderPacket(buf, args, 64, 1200);
}
