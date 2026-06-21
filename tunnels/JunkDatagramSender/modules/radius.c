#include "radius.h"

bool junkdatagramsenderRadiusGenerate(sbuf_t *buf, const junkdatagramsender_module_args_t *args)
{
    return junkdatagramsenderGeneratePlaceholderPacket(buf, args, 20, 4096);
}
