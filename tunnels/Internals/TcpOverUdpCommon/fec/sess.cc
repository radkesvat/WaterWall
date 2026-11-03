#include "sess.h"
#include "encoding.h"
#include <iostream>
#include <sys/socket.h>
#include <sys/fcntl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>

UDPSession *
UDPSession::Dial(const char *ip, uint16_t port) {
    struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(port);
    int ret = inet_pton(AF_INET, ip, &(saddr.sin_addr));

    if (ret == 1) { // do nothing
    } else if (ret == 0) { // try ipv6
        return UDPSession::dialIPv6(ip, port);
    } else if (ret == -1) {
        return nullptr;
    }

    int sockfd = socket(PF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        return nullptr;
    }
    if (connect(sockfd, (struct sockaddr *) &saddr, sizeof(struct sockaddr)) < 0) {
        close(sockfd);
        return nullptr;
    }

    return UDPSession::createSession(sockfd);
}

UDPSession *
UDPSession::DialWithOptions(const char *ip, uint16_t port, size_t dataShards, size_t parityShards) {
    auto sess = UDPSession::Dial(ip, port);
    if (sess == nullptr) {
        return nullptr;
    }

    if (dataShards > 0 && parityShards > 0) {
        sess->fec = FEC::New(3 * (dataShards + parityShards), dataShards, parityShards);
        sess->shards.resize(dataShards + parityShards, nullptr);
        sess->dataShards = dataShards;
        sess->parityShards = parityShards;
    }
    return sess;
};


UDPSession *
UDPSession::dialIPv6(const char *ip, uint16_t port) {
    struct sockaddr_in6 saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin6_family = AF_INET6;
    saddr.sin6_port = htons(port);
    if (inet_pton(AF_INET6, ip, &(saddr.sin6_addr)) != 1) {
        return nullptr;
    }

    int sockfd = socket(PF_INET6, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        return nullptr;
    }
    if (connect(sockfd, (struct sockaddr *) &saddr, sizeof(struct sockaddr_in6)) < 0) {
        close(sockfd);
        return nullptr;
    }

    return UDPSession::createSession(sockfd);
}

UDPSession *
UDPSession::createSession(int sockfd) {
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags < 0) {
        return nullptr;
    }

    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        return nullptr;
    }

    UDPSession *sess = new(UDPSession);
    sess->m_sockfd = sockfd;
    sess->m_kcp = ikcp_create(IUINT32(rand()), sess);
    sess->m_kcp->output = sess->out_wrapper;
    return sess;
}


void
UDPSession::Update(uint32_t current) noexcept {
    for (;;) {
        ssize_t n = recv(m_sockfd, m_buf, sizeof(m_buf), 0);
        if (n > 0) {
            if (fec.isEnabled()) {
                // decode FEC packet
                auto pkt = fec.Decode(m_buf, static_cast<size_t>(n));
                if (pkt.flag == typeData) {
                    auto ptr = pkt.data->data();
                    // we have 2B size, ignore for typeData
                    ikcp_input(m_kcp, (char *) (ptr + 2), pkt.data->size() - 2);
                }

                // allow FEC packet processing with correct flags.
                if (pkt.flag == typeData || pkt.flag == typeFEC) {
                    // input to FEC, and see if we can recover data.
                    auto recovered = fec.Input(pkt);

                    // we have some data recovered.
                    for (auto &r : recovered) {
                        // recovered data has at least 2B size.
                        if (r->size() > 2) {
                            auto ptr = r->data();
                            // decode packet size, which is also recovered.
                            uint16_t sz;
                            decode16u(ptr, &sz);

                            // the recovered packet size must be in the correct range.
                            if (sz >= 2 && sz <= r->size()) {
                                // input proper data to kcp
                                ikcp_input(m_kcp, (char *) (ptr + 2), sz - 2);
                                // std::cout << "sz:" << sz << std::endl;
                            }
                        }
                    }
                }
            } else { // fec disabled
                ikcp_input(m_kcp, (char *) (m_buf), n);
            }
        } else {
            break;
        }
    }
    m_kcp->current = current;
    ikcp_flush(m_kcp);
}

void
UDPSession::Destroy(UDPSession *sess) {
    if (nullptr == sess) return;
    if (0 != sess->m_sockfd) { close(sess->m_sockfd); }
    if (nullptr != sess->m_kcp) { ikcp_release(sess->m_kcp); }
    delete sess;
}

ssize_t
UDPSession::Read(char *buf, size_t sz) noexcept {
    if (m_streambufsiz > 0) {
        size_t n = m_streambufsiz;
        if (n > sz) {
            n = sz;
        }
        memcpy(buf, m_streambuf, n);

        m_streambufsiz -= n;
        if (m_streambufsiz != 0) {
            memmove(m_streambuf, m_streambuf + n, m_streambufsiz);
        }
        return n;
    }

    int psz = ikcp_peeksize(m_kcp);
    if (psz <= 0) {
        return 0;
    }

    if (psz <= sz) {
        return (ssize_t) ikcp_recv(m_kcp, buf, int(sz));
    } else {
        ikcp_recv(m_kcp, (char *) m_streambuf, sizeof(m_streambuf));
        memcpy(buf, m_streambuf, sz);
        m_streambufsiz = psz - sz;
        memmove(m_streambuf, m_streambuf + sz, psz - sz);
        return sz;
    }
}

ssize_t
UDPSession::Write(const char *buf, size_t sz) noexcept {
    int n = ikcp_send(m_kcp, const_cast<char *>(buf), int(sz));
    if (n == 0) {
        return sz;
    } else return n;
}

int
UDPSession::SetDSCP(int iptos) noexcept {
    iptos = (iptos << 2) & 0xFF;
    return setsockopt(this->m_sockfd, IPPROTO_IP, IP_TOS, &iptos, sizeof(iptos));
}

void
UDPSession::SetStreamMode(bool enable) noexcept {
    if (enable) {
        this->m_kcp->stream = 1;
    } else {
        this->m_kcp->stream = 0;
    }
}

int
UDPSession::out_wrapper(const char *buf, int len, struct IKCPCB *, void *user) {
    assert(user != nullptr);
    UDPSession *sess = static_cast<UDPSession *>(user);

    if (sess->fec.isEnabled()) {    // append FEC header
        // extend to len + fecHeaderSizePlus2
        // i.e. 4B seqid + 2B flag + 2B size
        memcpy(sess->m_buf + fecHeaderSizePlus2, buf, static_cast<size_t>(len));
        sess->fec.MarkData(sess->m_buf, static_cast<uint16_t>(len));
        sess->output(sess->m_buf, len + fecHeaderSizePlus2);

        // FEC calculation
        // copy "2B size + data" to shards
        auto slen = len + 2;
        sess->shards[sess->pkt_idx] =
                std::make_shared<std::vector<byte>>(&sess->m_buf[fecHeaderSize], &sess->m_buf[fecHeaderSize + slen]);

        // count number of data shards
        sess->pkt_idx++;
        if (sess->pkt_idx == sess->dataShards) { // we've collected enough data shards
            sess->fec.Encode(sess->shards);
            // send parity shards
            for (size_t i = sess->dataShards; i < sess->dataShards + sess->parityShards; i++) {
                // append header to parity shards
                // i.e. fecHeaderSize + data(2B size included)
                memcpy(sess->m_buf + fecHeaderSize, sess->shards[i]->data(), sess->shards[i]->size());
                sess->fec.MarkFEC(sess->m_buf);
                sess->output(sess->m_buf, sess->shards[i]->size() + fecHeaderSize);
            }

            // reset indexing
            sess->pkt_idx = 0;
        }
    } else { // No FEC, just send raw bytes,
        sess->output(buf, static_cast<size_t>(len));
    }
    return 0;
}

ssize_t
UDPSession::output(const void *buffer, size_t length) {
    ssize_t n = send(m_sockfd, buffer, length, 0);
    return n;
}
