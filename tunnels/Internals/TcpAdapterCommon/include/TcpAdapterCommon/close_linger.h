#pragma once

#include "line.h"
#include "local_widle_table.h"

static inline bool tcpAdapterShouldLingerOnClose(const line_t *line, bool linger_on_normal_close)
{
    return lineHasCloseLingerReason(line, kLineCloseLingerPeerWriteShutdown) ||
           (linger_on_normal_close && ! lineIsFallback(line));
}

/* Caller runs on the socket/table owner worker, has removed the socket's old
 * idle item and detached callbacks reaching line state, has verified that the
 * socket is established, and has transferred all accepted output to WIO. The
 * key wioGetID(io) must be unused in this table.
 *
 * On Linux, takes over a healthy socket while normal dispatch is open. It
 * flushes output for at most WIO_DEFAULT_CLOSE_TIMEOUT, shuts down sending, then
 * discards input until peer close, five seconds idle, or thirty seconds total.
 * The detached socket owns no line reference and stays in the supplied table
 * for shutdown drain. The table must outlive this socket cleanup.
 *
 * True means cleanup owns the socket, which may already have closed inline;
 * caller must not use it again. False leaves socket ownership unchanged and
 * asks the caller to use ordinary close. Unsupported platforms return false. */
bool tcpAdapterBeginCloseLinger(wio_t *io, local_idle_table_t *table);
