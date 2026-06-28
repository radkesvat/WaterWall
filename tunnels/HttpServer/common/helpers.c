#include "structure.h"

#include "loggers/network_logger.h"

sbuf_t *httpserverAllocBufferForLength(line_t *l, uint32_t len)
{
    buffer_pool_t *pool = lineGetBufferPool(l);
    uint32_t       small_size = bufferpoolGetSmallBufferSize(pool);
    uint32_t       large_size = bufferpoolGetLargeBufferSize(pool);

    if (len <= small_size)
    {
        return bufferpoolGetSmallBuffer(pool);
    }

    if (len <= large_size)
    {
        return bufferpoolGetLargeBuffer(pool);
    }

    return sbufCreateWithPadding(len, bufferpoolGetLargeBufferPadding(pool));
}
