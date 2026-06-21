#include "module.h"

static uint16_t junkdatagramsenderClampPacketSize(uint16_t value, uint16_t max_value)
{
    return value > max_value ? max_value : value;
}

bool junkdatagramsenderGeneratePlaceholderPacket(sbuf_t *buf, const junkdatagramsender_module_args_t *args,
                                                 uint16_t fallback_min_size, uint16_t fallback_max_size)
{
    if (buf == NULL || args == NULL)
    {
        return false;
    }

    uint32_t writable = sbufGetMaximumWriteableSize(buf);
    if (writable == 0)
    {
        return false;
    }

    uint16_t max_size = fallback_max_size;
    if (args->max_packet_size > 0 && args->max_packet_size < max_size)
    {
        max_size = args->max_packet_size;
    }
    max_size = junkdatagramsenderClampPacketSize(max_size, (uint16_t) min(writable, (uint32_t) UINT16_MAX));

    uint16_t min_size = fallback_min_size;
    if (args->min_packet_size > min_size)
    {
        min_size = args->min_packet_size;
    }
    if (min_size > max_size)
    {
        min_size = max_size;
    }

    uint32_t span = (uint32_t) max_size - (uint32_t) min_size + 1U;
    uint32_t len  = (uint32_t) min_size + (fastRand32() % span);

    sbufSetLength(buf, len);
    getRandomBytes(sbufGetMutablePtr(buf), len);
    return true;
}
