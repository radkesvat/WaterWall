#include "structure.h"

#include "loggers/network_logger.h"

void tcpoverudpclientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    tcpoverudpclient_lstate_t *ls = lineGetState(l, t);

    if (! tcpoverudpclientLinestateInitialize(ls, l, t))
    {
        // the next tunnel never received Init, so only the previous side may be closed here
        LOGE("TcpOverUdpClient: line state initialization failed, closing this line");
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    tunnelNextUpStreamInit(t, l);
}
