#include "structure.h"

#include "loggers/network_logger.h"

void tcpoverudpserverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    tcpoverudpserver_lstate_t *ls = lineGetState(l, t);

    if (! tcpoverudpserverLinestateInitialize(ls, l, t))
    {
        // the next tunnel never received Init, so only the previous side may be closed here
        LOGE("TcpOverUdpServer: line state initialization failed, closing this line");
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    tunnelNextUpStreamInit(t, l);
}
