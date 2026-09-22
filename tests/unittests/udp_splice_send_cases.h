/* Real private pipes and socket failure effects for udp_datagram_write_test.c. */
#if WW_HAVE_SPLICE
static int probe_pipe_error;
int        __real_pipe2(int pipefd[2], int flags);
int        __wrap_pipe2(int pipefd[2], int flags);
int        __wrap_pipe2(int pipefd[2], int flags)
{
    if (probe_pipe_error != 0)
    {
        errno            = probe_pipe_error;
        probe_pipe_error = 0;
        return -1;
    }
    return __real_pipe2(pipefd, flags);
}

static int        splice_error;
static bool       splice_short, discard_cork;
static int        observed_pipe = -1;
static unsigned   pipe_reads, splice_calls;
static sockaddr_u failure_peer;

ssize_t __real_splice(int in, loff_t *off_in, int out, loff_t *off_out, size_t length, unsigned flags);
ssize_t __wrap_splice(int in, loff_t *off_in, int out, loff_t *off_out, size_t length, unsigned flags);
ssize_t __real_read(int fd, void *buffer, size_t length);
ssize_t __wrap_read(int fd, void *buffer, size_t length);
ssize_t __wrap_read(int fd, void *buffer, size_t length)
{
    if (fd == observed_pipe)
        ++pipe_reads;
    return __real_read(fd, buffer, length);
}
ssize_t __wrap_splice(int in, loff_t *off_in, int out, loff_t *off_out, size_t length, unsigned flags)
{
    ++splice_calls;
    require((flags & SPLICE_F_MORE) != 0, "UDP splice must retain every internal chunk until commit");
    if (splice_error)
    {
        errno        = splice_error;
        splice_error = 0;
        return -1;
    }
    if (splice_short)
    {
        splice_short  = false;
        ssize_t moved = __real_splice(in, off_in, out, off_out, length / 2, flags);
        require(moved > 0, "failure injection must actually consume pipe bytes");
        if (discard_cork)
        {
            /* Induce a real append overflow after partial consumption. The kernel
             * discards pending assembly; the writer cannot infer this from a
             * positive short splice result. No malformed datagram is published. */
            static char overflow[65507];
            require(__real_sendto(
                        out, overflow, sizeof(overflow), MSG_MORE, &failure_peer.sa, SOCKADDR_LEN(&failure_peer)) < 0 &&
                        errno == EMSGSIZE,
                    "kernel did not discard overflowing assembly");
        }
        return moved;
    }
    return __real_splice(in, off_in, out, off_out, length, flags);
}

static sbuf_t *makePipePayload(buffer_pool_t *pool, uint32_t body, const char *prefix)
{
    sbuf_t *buf = bufferpoolGetSpliceBuffer(pool);
    require(buf != NULL, "get UDP private pipe");
    splice_buffer_metadata_t meta     = sbufSpliceMetadata(buf);
    int                      capacity = fcntl(meta.pipefd[1], F_GETPIPE_SZ);
    require(capacity > 0 && body <= (uint32_t) capacity, "fixture exceeds actual pipe capacity");
    char bytes[65536];
    memset(bytes, 'B', sizeof(bytes));
    require(body == 0 || write(meta.pipefd[1], bytes, body) == body, "populate UDP private pipe");
    buf->capacity = buf->l_pad + body;
    sbufSetLength(buf, body);
    uint32_t prefix_len = (uint32_t) strlen(prefix);
    sbufShiftLeft(buf, prefix_len);
    sbufWrite(buf, prefix, prefix_len);
    observed_pipe = meta.pipefd[0];
    pipe_reads = splice_calls = 0;
    return buf;
}
static int boundPeer(int family, const char *host, sockaddr_u *addr)
{
    int fd = socket(family, SOCK_DGRAM, 0);
    require(fd >= 0 && sockaddrSetIpAddressPort(addr, host, 0) == 0, "create UDP peer");
    require(bind(fd, &addr->sa, SOCKADDR_LEN(addr)) == 0 && nonBlocking(fd) == 0, "bind UDP peer");
    socklen_t size = sizeof(*addr);
    require(getsockname(fd, &addr->sa, &size) == 0, "query UDP peer");
    return fd;
}
static void expectPipeDatagram(int fd, uint32_t body, const char *prefix)
{
    char     bytes[65536];
    uint32_t prefix_len = (uint32_t) strlen(prefix);
    int      n          = (int) recv(fd, bytes, sizeof(bytes), 0);
    require(n == (int) (body + prefix_len), "UDP splice length or boundary changed");
    require(memcmp(bytes, prefix, prefix_len) == 0, "UDP splice prefix changed");
    for (uint32_t i = prefix_len; i < (uint32_t) n; ++i)
        require(bytes[i] == 'B', "UDP pipe body changed");
    require(recv(fd, bytes, sizeof(bytes), 0) < 0 && errno == EAGAIN, "extra UDP datagram emitted");
}
static void runProbeAllocationRefusalChecks(wloop_t *loop, buffer_pool_t *pool)
{
    sockaddr_u peer;
    int        receiver = boundPeer(AF_INET, "127.0.0.1", &peer);
    wio_t     *io       = wloopCreateUdpServer(loop, "127.0.0.1", 0);
    require(io != NULL, "probe refusal sender");
    const int errors[] = {EMFILE, ENFILE, ENOMEM};
    for (unsigned i = 0; i < ARRAY_SIZE(errors); ++i)
    {
        sbuf_t                  *buf  = makePipePayload(pool, 1400, "prefix");
        splice_buffer_metadata_t meta = sbufSpliceMetadata(buf);
        /* Unknown capacity must probe even on hosts that refuse source-pipe growth. */
        meta.pipe_capacity = 0;
        sbufSpliceSetMetadata(buf, meta);
        probe_pipe_error = errors[i];
        require(wioWriteDatagram(io, buf, &peer) == 1406, "probe refusal lost complete datagram");
        require(probe_pipe_error == 0 && pipe_reads > 0 && splice_calls == 0,
                "probe refusal must materialize before priming the socket");
        require(! wioIsClosed(io), "probe refusal retired an untouched socket");
        expectPipeDatagram(receiver, 1400, "prefix");
    }
    /* The same socket remains usable after every refused probe. */
    require(wioWriteDatagram(io, makePipePayload(pool, 17, ""), &peer) == 17, "post-refusal send");
    expectPipeDatagram(receiver, 17, "");
    wioClose(io);
    close(receiver);
}

static void runSegmentedAndTcpPipeChecks(wloop_t *loop, buffer_pool_t *pool)
{
    sockaddr_u peer;
    int        receiver = boundPeer(AF_INET, "127.0.0.1", &peer);
    wio_t     *io       = wloopCreateUdpServer(loop, "127.0.0.1", 0);
    require(io != NULL, "segmented pipe UDP sender");
    sbuf_t *buf = bufferpoolGetSpliceBuffer(pool);
    require(buf != NULL && sbufSpliceInitPipe(buf, 32U * 4096U) == 0, "segmented fixture pipe");
    splice_buffer_metadata_t meta     = sbufSpliceMetadata(buf);
    int                      capacity = fcntl(meta.pipefd[1], F_GETPIPE_SZ);
    unsigned                 segments = (unsigned) capacity / (unsigned) sysconf(_SC_PAGESIZE);
    if (segments > 32)
        segments = 32;
    require(segments > 0, "empty pipe capacity");
    char fragment[31];
    memset(fragment, 'B', sizeof(fragment));
    for (unsigned i = 0; i < segments; ++i)
    {
        int pipefd[2];
        require(pipe2(pipefd, O_NONBLOCK) == 0, "fragment pipe");
        require(write(pipefd[1], fragment, sizeof(fragment)) == sizeof(fragment), "fragment contents");
        require(__real_splice(pipefd[0], NULL, meta.pipefd[1], NULL, sizeof(fragment), SPLICE_F_NONBLOCK) ==
                    sizeof(fragment),
                "distinct pipe segment assembly");
        close(pipefd[0]);
        close(pipefd[1]);
    }
    uint32_t length = segments * sizeof(fragment);
    buf->capacity   = buf->l_pad + length;
    sbufSetLength(buf, length);
    observed_pipe = meta.pipefd[0];
    pipe_reads = splice_calls = 0;
    require(wioWriteDatagram(io, buf, &peer) == (int) length, "segmented pipe send");
    if (segments > 65536U / (unsigned) sysconf(_SC_PAGESIZE))
        require(pipe_reads > 0 && splice_calls == 0,
                "unsupported fragment layout must fall back before socket assembly");
    else
        require(pipe_reads == 0, "supported fragment layout unexpectedly materialized");
    expectPipeDatagram(receiver, length, "");

    /* A large resident prefix also spends the kernel skb fragment budget. */
    char large_prefix[60001];
    memset(large_prefix, 'P', sizeof(large_prefix) - 1);
    large_prefix[60000] = 0;
    buf                 = sbufCreateSplice(60000);
    require(sbufSpliceInitPipe(buf, 65536) == 0, "large-prefix pipe");
    meta     = sbufSpliceMetadata(buf);
    capacity = fcntl(meta.pipefd[1], F_GETPIPE_SZ);
    segments = (unsigned) capacity / (unsigned) sysconf(_SC_PAGESIZE);
    if (segments > 16)
        segments = 16;
    for (unsigned i = 0; i < segments; ++i)
    {
        int pipefd[2];
        require(pipe2(pipefd, O_NONBLOCK) == 0, "large-prefix fragment pipe");
        require(write(pipefd[1], fragment, sizeof(fragment)) == sizeof(fragment), "large-prefix fragment contents");
        require(__real_splice(pipefd[0], NULL, meta.pipefd[1], NULL, sizeof(fragment), SPLICE_F_NONBLOCK) ==
                    sizeof(fragment),
                "large-prefix distinct fragments");
        close(pipefd[0]);
        close(pipefd[1]);
    }
    length        = segments * sizeof(fragment);
    buf->capacity = buf->l_pad + length;
    sbufSetLength(buf, length);
    sbufShiftLeft(buf, 60000);
    sbufWrite(buf, large_prefix, 60000);
    udp_send_result_t sent = udpSendBuffer(wioGetFD(io), buf, &peer, false);
    require(sent.bytes == (int) (60000 + length) && ! sent.retire, "prefix fragment budget retired a valid datagram");
    expectPipeDatagram(receiver, length, large_prefix);
    sbufDestroy(buf);

    int        listener = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_u tcp_addr = {0};
    require(listener >= 0 && sockaddrSetIpAddressPort(&tcp_addr, "127.0.0.1", 0) == 0, "TCP fixture listener");
    require(bind(listener, &tcp_addr.sa, SOCKADDR_LEN(&tcp_addr)) == 0 && listen(listener, 1) == 0, "TCP fixture bind");
    socklen_t size = sizeof(tcp_addr);
    require(getsockname(listener, &tcp_addr.sa, &size) == 0, "TCP fixture address");
    int client = socket(AF_INET, SOCK_STREAM, 0);
    require(client >= 0 && connect(client, &tcp_addr.sa, SOCKADDR_LEN(&tcp_addr)) == 0, "TCP fixture connect");
    int server = accept(listener, NULL, NULL);
    require(server >= 0, "TCP fixture accept");
    buf = bufferpoolGetSpliceBuffer(pool);
    require(buf != NULL, "TCP receive pipe");
    meta = sbufSpliceMetadata(buf);
    char bytes[4000];
    memset(bytes, 'B', sizeof(bytes));
    require(send(client, bytes, sizeof(bytes), 0) == sizeof(bytes), "TCP fixture send");
    require(__real_splice(server, NULL, meta.pipefd[1], NULL, sizeof(bytes), 0) == sizeof(bytes),
            "TCP to private pipe");
    buf->capacity = buf->l_pad + sizeof(bytes);
    sbufSetLength(buf, sizeof(bytes));
    observed_pipe = meta.pipefd[0];
    pipe_reads = splice_calls = 0;
    require(wioWriteDatagram(io, buf, &peer) == sizeof(bytes) && pipe_reads == 0, "TCP-origin pipe UDP send");
    expectPipeDatagram(receiver, sizeof(bytes), "");
    close(server);
    close(client);
    close(listener);
    close(receiver);
    wioClose(io);
}

static void runSpliceUdpChecks(wloop_t *loop, buffer_pool_t *pool)
{
    bufferpoolUpdateAllocationPaddings(pool, 64, 64, 64, 64);
    for (unsigned family_case = 0; family_case < 3; ++family_case)
    {
        const int   family = family_case == 0 ? AF_INET : AF_INET6;
        const char *host   = family_case == 0 ? "127.0.0.1" : "::1";
        sockaddr_u  addr_a, addr_b;
        int         a = boundPeer(family_case == 2 ? AF_INET : family, family_case == 2 ? "127.0.0.1" : host, &addr_a);
        int         b = boundPeer(family_case == 2 ? AF_INET : family, family_case == 2 ? "127.0.0.1" : host, &addr_b);
        if (family_case == 2)
        {
            uint16_t pa = sockaddrPort(&addr_a), pb = sockaddrPort(&addr_b);
            require(sockaddrSetIpAddressPort(&addr_a, "::ffff:127.0.0.1", pa) == 0 &&
                        sockaddrSetIpAddressPort(&addr_b, "::ffff:127.0.0.1", pb) == 0,
                    "mapped destinations");
        }
        wio_t *io = wloopCreateUdpServer(loop, family_case == 2 ? "::" : host, 0);
        require(io != NULL, "create UDP splice WIO");
        for (unsigned connected = 0; connected < 2; ++connected)
        {
            if (connected)
                require(connect(wioGetFD(io), &addr_a.sa, SOCKADDR_LEN(&addr_a)) == 0, "connect UDP sender");
            const uint32_t bodies[]   = {0, 0, 4, 4000};
            const char    *prefixes[] = {"", "head", "", "head"};
            for (unsigned i = 0; i < 4; ++i)
            {
                sbuf_t *buf = makePipePayload(pool, bodies[i], prefixes[i]);
                require(wioWriteDatagram(io, buf, &addr_a) == (int) (bodies[i] + strlen(prefixes[i])),
                        "full UDP splice send");
                require(pipe_reads == 0 && splice_calls == (bodies[i] ? 1U : 0U),
                        "fast path read/materialized pipe body");
                expectPipeDatagram(a, bodies[i], prefixes[i]);
                buf = makePipePayload(pool, 4, "B-peer");
                wioSetPeerAddr(io, &addr_b.sa, SOCKADDR_LEN(&addr_b));
                require(wioWrite(io, buf) == 10, "generic UDP splice dispatch");
                expectPipeDatagram(b, 4, "B-peer");
                require(wioWriteDatagram(io, makePayload(pool, "ordinary"), &addr_a) == 8, "ordinary mixed send");
                expectDatagram(a, "ordinary", "ordinary fallback changed");
            }
        }
        /* Large resident prefix plus pipe still obeys total-datagram preflight. */
        sbuf_t *oversize = sbufCreateSplice(65504);
        require(sbufSpliceInitPipe(oversize, 0) == 0, "oversize fixture pipe");
        char body[24] = {0};
        require(write(sbufSpliceMetadata(oversize).pipefd[1], body, sizeof(body)) == sizeof(body),
                "oversize fixture body");
        oversize->capacity = oversize->l_pad + sizeof(body);
        sbufSetLength(oversize, sizeof(body));
        sbufShiftLeft(oversize, 65504);
        memset(sbufGetMutablePtr(oversize), 0, 65504);
        splice_calls               = 0;
        udp_send_result_t rejected = udpSendBuffer(wioGetFD(io), oversize, &addr_a, false);
        require(rejected.error == EMSGSIZE && ! rejected.retire && splice_calls == 0, "oversize touched socket");
        sbufDestroy(oversize);
        wioClose(io);
        close(a);
        close(b);
    }
    runSegmentedAndTcpPipeChecks(loop, pool);
    runProbeAllocationRefusalChecks(loop, pool);
    sockaddr_u peer;
    int        receiver = boundPeer(AF_INET, "127.0.0.1", &peer);
    const int  errors[] = {EINTR, EAGAIN, ENOBUFS, EMSGSIZE, EHOSTUNREACH};
    for (unsigned stage = 0; stage < 5; ++stage)
        for (unsigned e = 0; e < sizeof(errors) / sizeof(errors[0]); ++e)
        {
            wio_t *io = wloopCreateUdpServer(loop, "127.0.0.1", 0);
            require(io != NULL, "failure socket");
            sbuf_t *buf    = makePipePayload(pool, 4000, "head");
            int     reader = dup(sbufSpliceMetadata(buf).pipefd[0]);
            require(reader >= 0, "observe discarded pipe");
            if (stage == 0)
                force_sendto_errno = errors[e];
            if (stage == 1)
                splice_error = errors[e];
            if (stage == 2 || stage == 3)
            {
                splice_short = true;
                discard_cork = stage == 3;
                failure_peer = peer;
            }
            if (stage == 4)
                commit_error = errors[e];
            int sent = wioWriteDatagram(io, buf, &peer);
            require(sent <= 0, "partial UDP send reported success");
            require(wioIsClosed(io) == (stage != 0), "wrong retirement policy");
            char    byte;
            ssize_t n = read(reader, &byte, 1);
            require(n == 0 || (n < 0 && errno == EAGAIN), "failure leaked pipe bytes");
            close(reader);
            expectNoDatagram(receiver, "failed assembly leaked prefix/suffix");
            if (stage != 0)
            {
                require(wioWriteDatagram(io, makePayload(pool, "stale"), &peer) == -1, "retired WIO accepted write");
                io = wloopCreateUdpServer(loop, "127.0.0.1", 0);
            }
            require(wioWriteDatagram(io, makePayload(pool, "clean"), &peer) == 5, "safe next send failed");
            expectDatagram(receiver, "clean", "pending assembly contaminated next send");
            wioClose(io);
        }
    observed_pipe = -1;
    close(receiver);
}
#endif
