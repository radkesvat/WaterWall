/* Real private pipes and socket failure effects for udp_datagram_write_test.c. */
#if WW_HAVE_SPLICE
static int      observed_pipe = -1;
static unsigned pipe_reads, splice_calls;

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
    pipe_reads = splice_calls = udp_sendto_calls = 0;
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
    require(pipe_reads > 0 && splice_calls == 0, "segmented UDP body was not materialized");
    expectPipeDatagram(receiver, length, "");

    /* Materialization includes the complete resident prefix and every pipe range. */
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
    observed_pipe = meta.pipefd[0];
    pipe_reads = splice_calls = udp_sendto_calls = 0;
    udp_send_result_t sent                       = udpSendBuffer(wioGetFD(io), pool, buf, &peer, false);
    require(sent.bytes == (int) (60000 + length) && ! sent.retire, "large-prefix datagram send failed");
    require(pipe_reads > 0 && splice_calls == 0 && udp_sendto_calls == 1 && udp_sendto_flags == 0 &&
                udp_sendto_length == 60000 + length && sbufGetLength(buf) == 0,
            "large-prefix materialization changed send geometry or ownership");
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
    require(wioWriteDatagram(io, buf, &peer) == sizeof(bytes) && pipe_reads > 0 && splice_calls == 0,
            "TCP-origin pipe UDP send did not materialize");
    expectPipeDatagram(receiver, sizeof(bytes), "");
    close(server);
    close(client);
    close(listener);
    close(receiver);
    wioClose(io);
}

static void checkOddFragmentDatagram(wio_t *io, buffer_pool_t *pool, const sockaddr_u *peer, int receiver)
{
    // Distinct short fragments must remain one intact datagram.
    const char *parts[] = {"abc", "DEFGH"};
    sbuf_t     *buf     = bufferpoolGetSpliceBuffer(pool);
    require(buf != NULL, "odd-fragment private pipe");
    splice_buffer_metadata_t meta = sbufSpliceMetadata(buf);
    for (unsigned i = 0; i < ARRAY_SIZE(parts); ++i)
    {
        int    pipefd[2];
        size_t length = strlen(parts[i]);
        require(pipe2(pipefd, O_NONBLOCK | O_CLOEXEC) == 0, "odd fragment source pipe");
        require(write(pipefd[1], parts[i], length) == (ssize_t) length, "odd fragment source bytes");
        require(__real_splice(pipefd[0], NULL, meta.pipefd[1], NULL, length, SPLICE_F_NONBLOCK) == (ssize_t) length,
                "odd fragment assembly");
        close(pipefd[0]);
        close(pipefd[1]);
    }
    buf->capacity = buf->l_pad + 8;
    sbufSetLength(buf, 8);
    observed_pipe = meta.pipefd[0];
    pipe_reads = splice_calls = udp_sendto_calls = 0;
    require(wioWriteDatagram(io, buf, peer) == 8, "odd-fragment UDP send failed");
    require(pipe_reads > 0 && splice_calls == 0 && udp_sendto_calls == 1 && udp_sendto_length == 8 &&
                udp_sendto_flags == 0,
            "UDP pipe body must materialize before one ordinary socket send");
    expectDatagram(receiver, "abcDEFGH", "odd-fragment UDP bytes/checksum changed");
    expectNoDatagram(receiver, "odd-fragment send emitted extra datagrams");
}

static void runPooledMaterializationChecks(wloop_t *loop, buffer_pool_t *pool)
{
    sockaddr_u peer;
    int        receiver = boundPeer(AF_INET, "127.0.0.1", &peer);
    wio_t     *io       = wloopCreateUdpServer(loop, "127.0.0.1", 0);
    require(io != NULL, "pooled materialization socket");
    const uint32_t bodies[] = {17, 1400, 4000};
    for (unsigned i = 0; i < ARRAY_SIZE(bodies); ++i)
        for (unsigned fail = 0; fail < 2; ++fail)
        {
            sbuf_t        *buf    = makePipePayload(pool, bodies[i], "head");
            const uint32_t length = sbufGetLength(buf);
#if BYPASS_BUFFERPOOL != 1
            sbuf_t   *cached   = bufferpoolGetBestFit(pool, length, 0);
            uintptr_t expected = (uintptr_t) sbufGetRawPtr(cached);
            bufferpoolReuseBuffer(pool, cached);
#endif
            force_sendto_errno       = fail ? EAGAIN : 0;
            udp_send_result_t result = udpSendBuffer(wioGetFD(io), pool, buf, &peer, false);
            require(result.bytes == (fail ? -1 : (int) length) && result.error == (fail ? EAGAIN : 0) &&
                        ! result.retire && sbufGetLength(buf) == 0,
                    "pooled materialization changed send results or input ownership");
#if BYPASS_BUFFERPOOL != 1
            require(udp_sendto_data == expected, "materialization did not borrow the best-fit cached buffer");
            cached = bufferpoolGetBestFit(pool, length, 0);
            require((uintptr_t) sbufGetRawPtr(cached) == expected && sbufGetLength(cached) == 0,
                    "materialization did not return its temporary buffer on success or failure");
            bufferpoolReuseBuffer(pool, cached);
#endif
            bufferpoolReuseBuffer(pool, buf);
            if (fail)
                expectNoDatagram(receiver, "failed pooled send emitted a datagram");
            else
                expectPipeDatagram(receiver, bodies[i], "head");
        }
    wioClose(io);
    close(receiver);
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
            checkOddFragmentDatagram(io, pool, &addr_a, a);
            const uint32_t bodies[]   = {0, 0, 4, 4000};
            const char    *prefixes[] = {"", "head", "", "head"};
            for (unsigned i = 0; i < 4; ++i)
            {
                sbuf_t *buf = makePipePayload(pool, bodies[i], prefixes[i]);
                require(wioWriteDatagram(io, buf, &addr_a) == (int) (bodies[i] + strlen(prefixes[i])),
                        "full UDP splice send");
                require((pipe_reads > 0) == (bodies[i] != 0) && splice_calls == 0 && udp_sendto_calls == 1 &&
                            udp_sendto_flags == 0 && udp_sendto_length == bodies[i] + strlen(prefixes[i]),
                        "UDP input did not use one complete ordinary send");
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
        observed_pipe = sbufSpliceMetadata(oversize).pipefd[0];
        pipe_reads = splice_calls = udp_sendto_calls = 0;
        udp_send_result_t rejected                   = udpSendBuffer(wioGetFD(io), pool, oversize, &addr_a, false);
        require(rejected.error == EMSGSIZE && ! rejected.retire && splice_calls == 0 && pipe_reads == 0 &&
                    udp_sendto_calls == 0 && sbufGetLength(oversize) == 65528,
                "oversize touched socket or consumed input");
        sbufDestroy(oversize);
        wioClose(io);
        close(a);
        close(b);
    }
    runSegmentedAndTcpPipeChecks(loop, pool);
    runPooledMaterializationChecks(loop, pool);
    sockaddr_u peer;
    int        receiver = boundPeer(AF_INET, "127.0.0.1", &peer);
    const int  errors[] = {EINTR, EAGAIN, ENOBUFS, EMSGSIZE, EHOSTUNREACH};
    for (unsigned e = 0; e < ARRAY_SIZE(errors); ++e)
    {
        wio_t *io = wloopCreateUdpServer(loop, "127.0.0.1", 0);
        require(io != NULL, "failure socket");
        sbuf_t *buf    = makePipePayload(pool, 4000, "head");
        int     reader = dup(sbufSpliceMetadata(buf).pipefd[0]);
        require(reader >= 0, "observe discarded pipe");
        force_sendto_errno   = errors[e];
        int        sent      = wioWriteDatagram(io, buf, &peer);
        const bool transient = errors[e] == EINTR || errors[e] == EAGAIN || errors[e] == ENOBUFS;
        require(sent == (transient ? 0 : -1) && ! wioIsClosed(io), "materialized send changed error policy");
        require(wioGetWriteBufSize(io) == 0 && ! (wioGetEvents(io) & WW_WRITE), "failed UDP write was queued");
        require(pipe_reads > 0 && splice_calls == 0 && udp_sendto_calls == 1 && udp_sendto_length == 4004 &&
                    udp_sendto_flags == 0,
                "failed send did not materialize the complete datagram");
        char    byte;
        ssize_t n = read(reader, &byte, 1);
        require(n == 0 || (n < 0 && errno == EAGAIN), "failure leaked pipe bytes");
        close(reader);
        expectNoDatagram(receiver, "failed send leaked a datagram");
        require(wioWriteDatagram(io, makePayload(pool, "clean"), &peer) == 5, "safe next send failed");
        expectDatagram(receiver, "clean", "failed send contaminated next send");
        wioClose(io);
    }
    /* Retrying EINTR reuses the materialized bytes, never the consumed pipe. */
    wio_t *io = wloopCreateUdpServer(loop, "127.0.0.1", 0);
    require(io != NULL, "EINTR policy socket");
    for (unsigned retry = 0; retry < 2; ++retry)
    {
        sbuf_t *buf              = makePipePayload(pool, 4000, "head");
        force_sendto_errno       = EINTR;
        udp_send_result_t result = udpSendBuffer(wioGetFD(io), pool, buf, &peer, retry != 0);
        require(result.bytes == (retry ? 4004 : -1) && result.error == (retry ? 0 : EINTR) && ! result.retire,
                "materialized send changed EINTR retry policy");
        require(sbufGetLength(buf) == 0 && pipe_reads > 0 && splice_calls == 0 && udp_sendto_calls == retry + 1 &&
                    udp_sendto_length == 4004 && udp_sendto_flags == 0,
                "EINTR retry lost source ownership or datagram bytes");
        bufferpoolReuseBuffer(pool, buf);
        if (retry)
            expectPipeDatagram(receiver, 4000, "head");
        else
            expectNoDatagram(receiver, "non-retried EINTR sent a datagram");
    }
    wioClose(io);
    observed_pipe = -1;
    close(receiver);
}
#endif
