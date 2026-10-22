/* Production raw QUIC bridge: authenticated v1 handshake, opening marker,
 * bidirectional binary stream, loss/reordering, ACK-only credit, hard limits,
 * certificate/ALPN failures and synchronous retirement. Checks survive NDEBUG. */
#include "quic_engine.h"
#include "test_assert.h"

/* Same translation unit as production code permits a deliberately abnormal
 * raw peer without adding test-only hooks to the C ABI or the node runtime. */
#include "quic_engine.cc"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

namespace
{
using Config = std::unique_ptr<ww_quic_config_t, decltype(&ww_quic_config_destroy)>;
using Engine = std::unique_ptr<ww_quic_engine_t, decltype(&ww_quic_engine_destroy)>;

ww_quic_settings_t Settings(bool client)
{
    ww_quic_settings_t s{};
    s.is_client            = client;
    s.verify               = true;
    s.protocol             = "h3";
    s.sni                  = "tls.integration.test";
    s.ca_file              = QUIC_TEST_CERT;
    s.cert_file            = QUIC_TEST_CERT;
    s.key_file             = QUIC_TEST_KEY;
    s.handshake_timeout_ms = 2000;
    s.idle_timeout_ms      = 5000;
    s.max_packet_size      = 1350;
    s.max_buffered_bytes   = 128 * 1024;
    s.max_buffered_buffers = 1024;
    s.receive_window_bytes = 65536;
    s.allocate             = &std::malloc;
    s.deallocate           = &std::free;
    s.fatal                = &std::abort;
    return s;
}
Config CreateConfig(ww_quic_settings_t s)
{
    char   error[256];
    Config config(ww_quic_config_create(&s, error, sizeof(error)), ww_quic_config_destroy);
    if (! config)
        std::fprintf(stderr, "config error: %s\n", error);
    require(config != nullptr, "valid engine settings rejected");
    return config;
}

struct Pair
{
    struct Packet
    {
        bool                 to_client;
        std::vector<uint8_t> bytes;
    };
    Config             client_config;
    Config             server_config;
    Engine             client;
    Engine             server;
    std::deque<Packet> packets;
    std::string        client_bytes;
    std::string        server_bytes;
    bool               client_ready = false, server_ready = false;
    bool               impairment     = false;
    bool               dropped        = false;
    bool               dropped_marker = false;
    size_t             packet_number  = 0;

    Pair(ww_quic_settings_t cs = Settings(true), ww_quic_settings_t ss = Settings(false))
        : client_config(CreateConfig(cs)), server_config(CreateConfig(ss)),
          client(ww_quic_engine_create(client_config.get()), ww_quic_engine_destroy),
          server(ww_quic_engine_create(server_config.get()), ww_quic_engine_destroy)
    {
        require(client && server, "engine allocation failed");
        require(ww_quic_engine_start(server.get()), "server start failed");
        require(ww_quic_engine_start(client.get()), "client start failed");
    }
    void Collect(ww_quic_engine_t *engine, bool from_client)
    {
        ww_quic_event_t event;
        while (ww_quic_engine_peek(engine, &event))
        {
            if (event.type == WW_QUIC_EVENT_DATAGRAM)
            {
                require(event.length >= 1 && event.length <= 1350, "packet writer violated configured datagram size");
                ++packet_number;
                if (impairment && ! dropped)
                    dropped = true; // one lost handshake packet must be retransmitted by real alarms
                else if (impairment && from_client && ww_quic_engine_ready(engine) && ! server_ready &&
                         ! dropped_marker)
                    dropped_marker = true; // retransmit the encrypted stream-opening flight too
                else
                {
                    Packet packet{! from_client, {event.data, event.data + event.length}};
                    if (impairment && packet_number % 5 == 0)
                        packets.push_front(packet); // bounded deterministic reorder
                    else
                        packets.push_back(packet);
                    if (impairment && packet_number % 7 == 0)
                        packets.push_back(packet);
                }
            }
            else if (event.type == WW_QUIC_EVENT_PLAINTEXT)
                (from_client ? client_bytes : server_bytes)
                    .append(reinterpret_cast<const char *>(event.data), event.length);
            else if (event.type == WW_QUIC_EVENT_READY)
                (from_client ? client_ready : server_ready) = true;
            ww_quic_engine_consume(engine);
        }
    }
    void Step()
    {
        Collect(client.get(), true);
        Collect(server.get(), false);
        size_t work = std::min<size_t>(packets.size(), 64);
        while (work--)
        {
            Packet packet = std::move(packets.front());
            packets.pop_front();
            auto *destination = packet.to_client ? client.get() : server.get();
            ww_quic_engine_feed(destination, packet.bytes.data(), packet.bytes.size());
            Collect(destination, packet.to_client);
        }
        ww_quic_engine_tick(client.get());
        ww_quic_engine_tick(server.get());
    }
    template <class Predicate> bool Until(Predicate condition, uint64_t timeout_us = 4000000)
    {
        uint64_t end = ww_quic_now_us() + timeout_us;
        do
        {
            Step();
            if (condition())
                return true;
            if (packets.empty())
                std::this_thread::sleep_for(std::chrono::microseconds(200));
        } while (ww_quic_now_us() < end);
        return false;
    }
    void Handshake()
    {
        bool success = Until([&] {
            return (client_ready && server_ready) || ww_quic_engine_closed(client.get()) ||
                   ww_quic_engine_closed(server.get());
        });
        if (! client_ready || ! server_ready)
            std::fprintf(stderr,
                         "client: %s; server: %s\n",
                         ww_quic_engine_error(client.get()),
                         ww_quic_engine_error(server.get()));
        require(success && client_ready && server_ready, "authenticated QUIC handshake/opening marker failed");
        require(client_bytes.empty() && server_bytes.empty(), "opening marker leaked into application");
    }
};

std::string Payload(size_t size)
{
    std::string value(size, '\0');
    for (size_t i = 0; i < size; ++i)
        value[i] = static_cast<char>((i * 151 + i / 13) & 255);
    return value;
}

void TestRoundtrip(bool impairment, const char *protocol)
{
    auto cs = Settings(true), ss = Settings(false);
    cs.protocol = ss.protocol = protocol;
    Pair pair(cs, ss);
    pair.impairment = impairment;
    pair.Handshake();
    require(! impairment || (pair.dropped && pair.dropped_marker),
            "impairment fixture did not drop handshake and opening flights");
    // Client sends no application bytes: the opening marker alone permits
    // server-first data, including a genuine initial application zero byte.
    std::string server_first("\0server-first\xff", 14);
    require(ww_quic_engine_write(
                pair.server.get(), reinterpret_cast<const uint8_t *>(server_first.data()), server_first.size()),
            "server-first write refused");
    require(pair.Until([&] { return pair.client_bytes == server_first; }), "server-first bytes not delivered");
    require(pair.server_bytes.empty(), "client marker reached server application");

    std::string sent          = Payload(512 * 1024);
    size_t      client_offset = 0, server_offset = 0;
    bool        delivered = pair.Until(
        [&] {
            if (client_offset < sent.size())
            {
                size_t size = std::min<size_t>(WW_QUIC_WRITE_CHUNK, sent.size() - client_offset);
                if (ww_quic_engine_write(
                        pair.client.get(), reinterpret_cast<const uint8_t *>(sent.data() + client_offset), size))
                    client_offset += size;
            }
            if (server_offset < sent.size())
            {
                size_t size = std::min<size_t>(WW_QUIC_WRITE_CHUNK, sent.size() - server_offset);
                if (ww_quic_engine_write(
                        pair.server.get(), reinterpret_cast<const uint8_t *>(sent.data() + server_offset), size))
                    server_offset += size;
            }
            return pair.server_bytes == sent && pair.client_bytes == server_first + sent;
        },
        8000000);
    require(delivered, "bidirectional binary stream lost data or order");
    require(! ww_quic_engine_closed(pair.client.get()) && ! ww_quic_engine_closed(pair.server.get()),
            "successful association closed prematurely");
    require(pair.Until([&] {
        ww_quic_storage_t c{}, s{};
        ww_quic_engine_storage(pair.client.get(), &c);
        ww_quic_engine_storage(pair.server.get(), &s);
        return c.send_bytes == 0 && s.send_bytes == 0;
    }),
            "ACK-only input did not release retained send ledger");
    ww_quic_engine_close(pair.client.get());
    require(ww_quic_engine_deadline(pair.client.get()) == UINT64_MAX, "retired engine retained alarm deadline");
    ww_quic_storage_t storage{};
    ww_quic_engine_storage(pair.client.get(), &storage);
    require(storage.send_bytes == 0 && storage.send_entries == 0 && storage.wire_entries == 0 &&
                storage.plaintext_entries == 0,
            "retirement retained owned bytes");
}

void TestFailure(const char *name, ww_quic_settings_t client, ww_quic_settings_t server)
{
    Pair pair(client, server);
    bool terminal = pair.Until(
        [&] { return ww_quic_engine_closed(pair.client.get()) || ww_quic_engine_closed(pair.server.get()); });
    if (! terminal)
        std::fprintf(stderr, "missing expected failure: %s\n", name);
    require(terminal && ! pair.server_ready, "invalid peer reached application readiness");
}

void TestAdmission()
{
    auto cs = Settings(true), ss = Settings(false);
    cs.max_buffered_buffers = 8;
    Pair pair(cs, ss);
    pair.Handshake();
    pair.Collect(pair.client.get(), true);
    pair.Collect(pair.server.get(), false);
    // Do not deliver any further packets, so ledger entries cannot be ACKed.
    std::string data     = Payload(1);
    size_t      accepted = 0;
    while (accepted < 100 &&
           ww_quic_engine_write(pair.client.get(), reinterpret_cast<const uint8_t *>(data.data()), data.size()))
        ++accepted;
    ww_quic_storage_t before{}, after{};
    ww_quic_engine_storage(pair.client.get(), &before);
    require(accepted > 0 && accepted <= 8 && before.send_entries == 8, "hard ledger entry budget was bypassed");
    require(! ww_quic_engine_closed(pair.client.get()), "ledger refusal incorrectly closed the standalone engine");
    require(! ww_quic_engine_write(pair.client.get(), reinterpret_cast<const uint8_t *>(data.data()), data.size()),
            "full send ledger accepted another chunk");
    ww_quic_engine_storage(pair.client.get(), &after);
    require(after.send_bytes == before.send_bytes && after.send_entries == before.send_entries,
            "refused write consumed input or created credit");
    require(pair.Until([&] {
        ww_quic_engine_storage(pair.client.get(), &after);
        return after.send_bytes == 0;
    }),
            "ACK-only recovery failed after bounded admission refusal");
}

void TestDeadline()
{
    auto settings                 = Settings(false);
    settings.handshake_timeout_ms = 20;
    Config config                 = CreateConfig(settings);
    Engine engine(ww_quic_engine_create(config.get()), ww_quic_engine_destroy);
    require(ww_quic_engine_start(engine.get()), "unopened server start failed");
    uint64_t      initial_deadline = ww_quic_engine_deadline(engine.get());
    const uint8_t irrelevant[]     = {0x00, 0x01, 0x02};
    uint64_t      end              = ww_quic_now_us() + 100000;
    while (! ww_quic_engine_closed(engine.get()) && ww_quic_now_us() < end)
    {
        ww_quic_engine_feed(engine.get(), irrelevant, sizeof(irrelevant));
        require(ww_quic_engine_closed(engine.get()) || ww_quic_engine_deadline(engine.get()) == initial_deadline,
                "irrelevant slow-drip input postponed total handshake deadline");
        ww_quic_engine_tick(engine.get());
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    require(ww_quic_engine_closed(engine.get()), "unopened stream deadline did not close association");
    require(ww_quic_engine_deadline(engine.get()) == UINT64_MAX, "expired association retained alarms");
}

void TestIdle()
{
    auto client = Settings(true), server = Settings(false);
    client.idle_timeout_ms = server.idle_timeout_ms = 80;
    Pair pair(client, server);
    pair.Handshake();
    // Stop delivering every peer packet. QUIC's keepalive transmissions must
    // not extend the local receive-idle deadline indefinitely.
    uint64_t end = ww_quic_now_us() + 1000000;
    while (! ww_quic_engine_closed(pair.client.get()) && ww_quic_now_us() < end)
    {
        pair.Collect(pair.client.get(), true);
        ww_quic_engine_tick(pair.client.get());
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    require(ww_quic_engine_closed(pair.client.get()), "silent peer did not reach QUIC idle timeout");
}

void TestFinalFlush()
{
    Pair pair;
    pair.Handshake();
    const std::string report("final-report\0", 13);
    require(ww_quic_engine_write(pair.server.get(), reinterpret_cast<const uint8_t *>(report.data()), report.size()),
            "final report was refused on writable stream");
    require(ww_quic_engine_flush(pair.server.get()), "synchronous final write pump failed");
    pair.Collect(pair.server.get(), false);
    ww_quic_engine_close(pair.server.get());
    require(pair.Until([&] { return pair.client_bytes == report; }),
            "already-staged final bytes were lost after immediate sender retirement");
}

void SuppressClientOpening(Pair &pair)
{
    // Suppress only the bridge's private opening protocol. TLS, QUIC packet
    // protection, server parsing, alarms and stream handling remain production.
    pair.client->stream_open = true;
    pair.client->marker_sent = true;
    require(pair.Until([&] { return pair.client->handshake_ready && pair.server->handshake_ready; }),
            "abnormal peer did not complete the authenticated TLS handshake");
    require(! ww_quic_engine_ready(pair.server.get()), "TLS completion incorrectly released application readiness");
}

void TestInvalidOpening()
{
    Pair pair;
    SuppressClientOpening(pair);
    require(pair.client->session->CanOpenNextOutgoingBidirectionalStream(), "first stream had no peer credit");
    auto *stream = pair.client->session->OpenOutgoingBidirectionalStream();
    require(stream && stream->GetStreamId() == 0, "abnormal peer did not open client stream zero");
    require(stream->Write("\x7f-invalid-opening"), "abnormal peer opening write refused");
    require(pair.Until([&] { return ww_quic_engine_closed(pair.server.get()); }), "invalid opening byte was accepted");
    require(! pair.server_ready && pair.server_bytes.empty(), "invalid opening content reached the application");
    require(std::strstr(ww_quic_engine_error(pair.server.get()), "opening byte") != nullptr,
            "invalid marker did not use the opening-byte failure path");
}

void TestMissingOpening()
{
    auto server                 = Settings(false);
    server.handshake_timeout_ms = 150;
    Pair pair(Settings(true), server);
    SuppressClientOpening(pair);
    const uint8_t server_first = 0x42;
    require(! ww_quic_engine_write(pair.server.get(), &server_first, 1),
            "server-first data was admitted before the opening marker");
    require(pair.Until(
                [&] {
                    const uint8_t irrelevant[] = {0, 1, 2};
                    ww_quic_engine_feed(pair.server.get(), irrelevant, sizeof(irrelevant));
                    return ww_quic_engine_closed(pair.server.get());
                },
                1000000),
            "authenticated peer missing its marker did not reach the total opening deadline");
    require(! pair.server_ready && pair.server_bytes.empty(), "missing marker reached application readiness");
    require(std::strstr(ww_quic_engine_error(pair.server.get()), "stream-opening deadline") != nullptr,
            "missing marker did not use the total stream-opening deadline");
}

void TestExtraStream(bool from_server, bool unidirectional)
{
    Pair pair;
    pair.Handshake();
    auto *sender   = from_server ? pair.server.get() : pair.client.get();
    auto *receiver = from_server ? pair.client.get() : pair.server.get();
    // A nonconforming peer can ignore MAX_STREAMS. Grant it local permission
    // only; the receiving production connection keeps its genuine wire limit.
    quic::QuicMaxStreamsFrame dishonest_credit(0, unidirectional || from_server ? 1 : 2, unidirectional);
    require(sender->session->OnMaxStreamsFrame(dishonest_credit), "peer-side stream-credit setup failed");
    auto *extra = unidirectional ? sender->session->OpenOutgoingUnidirectionalStream()
                                 : sender->session->OpenOutgoingBidirectionalStream();
    require(extra != nullptr && extra->Write("extra-stream"), "nonconforming peer did not emit extra STREAM data");
    require(pair.Until([&] { return ww_quic_engine_closed(receiver); }), "extra application stream was accepted");
    require(pair.server_bytes.empty() && pair.client_bytes.empty(), "extra stream was exposed to an application");
}

void TestCorruptAndIrrelevantPacket()
{
    Pair pair;
    pair.Handshake();
    pair.Collect(pair.client.get(), true);
    pair.Collect(pair.server.get(), false);
    const std::string payload = Payload(4096);
    require(ww_quic_engine_write(pair.client.get(), reinterpret_cast<const uint8_t *>(payload.data()), payload.size()),
            "corruption fixture payload refused");
    pair.Collect(pair.client.get(), true);
    auto selected = std::find_if(pair.packets.begin(), pair.packets.end(), [](const Pair::Packet &packet) {
        return ! packet.to_client && packet.bytes.size() > 256 && ! (packet.bytes[0] & 0x80);
    });
    require(selected != pair.packets.end(), "no protected application packet available for corruption");
    auto original = std::move(selected->bytes);
    pair.packets.erase(selected); // Recovery must retransmit this packet's stream bytes.
    auto corrupt = original;
    corrupt.back() ^= 0x80;
    ww_quic_engine_feed(pair.server.get(), corrupt.data(), corrupt.size());
    auto other_cid = original;
    other_cid[1] ^= 0x80; // First byte of the fixed eight-byte short-header destination CID.
    ww_quic_engine_feed(pair.server.get(), other_cid.data(), other_cid.size());
    pair.Collect(pair.server.get(), false);
    require(! ww_quic_engine_closed(pair.server.get()) && pair.server_bytes.empty(),
            "unauthentic or irrelevant-CID input closed the association or released plaintext");
    require(pair.Until([&] { return pair.server_bytes == payload; }),
            "corrupted packet silently lost accepted stream bytes");
    require(! ww_quic_engine_closed(pair.server.get()), "recovered association closed prematurely");
}

void TestPartialAckLedger()
{
    Pair pair;
    pair.Handshake();
    require(pair.Until([&] {
        ww_quic_storage_t storage{};
        ww_quic_engine_storage(pair.client.get(), &storage);
        return storage.send_bytes == 0;
    }),
            "opening marker was not acknowledged before ledger fixture");
    const std::string first(64, 'a'), second(96, 'b');
    require(
        ww_quic_engine_write(pair.client.get(), reinterpret_cast<const uint8_t *>(first.data()), first.size()) &&
            ww_quic_engine_write(pair.client.get(), reinterpret_cast<const uint8_t *>(second.data()), second.size()),
        "ledger fixture writes were refused");
    ww_quic_storage_t before{}, after{};
    ww_quic_engine_storage(pair.client.get(), &before);
    auto *stream = pair.client->session->GetActiveStream(0);
    require(stream && before.send_bytes == first.size() + second.size() && before.send_entries == 2,
            "ledger fixture did not retain both accepted chunks");
    uint64_t first_offset  = pair.client->ledger.front().offset;
    uint64_t sent_end      = first_offset + first.size() + second.size();
    uint64_t send_deadline = ww_quic_now_us() + 500000;
    while (stream->stream_bytes_written() < sent_end && ww_quic_now_us() < send_deadline)
    {
        ww_quic_engine_tick(pair.client.get());
        pair.Collect(pair.client.get(), true);
        std::this_thread::sleep_for(std::chrono::microseconds(200));
    }
    require(stream->stream_bytes_written() >= sent_end, "ledger fixture attempted to acknowledge unsent bytes");
    quic::QuicByteCount newly_acked = 0;
    // Inject ACK delivery at QUICHE's public stream handler, isolating ledger
    // retirement from network timing while retaining actual library ACK state.
    stream->OnStreamFrameAcked(
        first_offset + first.size(), second.size(), false, quic::QuicTime::Delta::Zero(), &newly_acked, false);
    pair.client->Reap();
    ww_quic_engine_storage(pair.client.get(), &after);
    require(after.send_bytes == before.send_bytes && after.send_entries == before.send_entries &&
                after.send_allocation == before.send_allocation,
            "later acknowledged chunk bypassed an earlier ledger gap");
    stream->OnStreamFrameAcked(first_offset + 32, 32, false, quic::QuicTime::Delta::Zero(), &newly_acked, false);
    pair.client->Reap();
    ww_quic_engine_storage(pair.client.get(), &after);
    require(after.send_bytes == before.send_bytes && after.send_entries == 2,
            "partial ACK released a whole retained chunk");
    stream->OnStreamFrameAcked(first_offset + 32, 32, false, quic::QuicTime::Delta::Zero(), &newly_acked, false);
    require(newly_acked == 0, "duplicate ACK created library send credit");
    pair.client->Reap();
    ww_quic_engine_storage(pair.client.get(), &after);
    require(after.send_bytes == before.send_bytes && after.send_allocation == before.send_allocation,
            "duplicate ACK created bridge admission credit");
    stream->OnStreamFrameAcked(first_offset, 32, false, quic::QuicTime::Delta::Zero(), &newly_acked, false);
    pair.client->Reap();
    ww_quic_engine_storage(pair.client.get(), &after);
    require(after.send_bytes == 0 && after.send_entries == 0 &&
                after.send_allocation == size_t(Settings(true).max_buffered_buffers) * WW_QUIC_SEND_DESCRIPTOR_CHARGE,
            "closing the front ACK gap did not retire the complete acknowledged ledger prefix");
}

void TestConfig()
{
    auto settings = Settings(true);
    char error[256];
    settings.sni = "non-ascii-\xc3\xa9.test";
    require(ww_quic_config_create(&settings, error, sizeof(error)) == nullptr, "non-ASCII SNI accepted");
    settings          = Settings(true);
    settings.protocol = "";
    require(ww_quic_config_create(&settings, error, sizeof(error)) == nullptr, "empty ALPN accepted");
    settings                 = Settings(true);
    settings.max_packet_size = 1199;
    require(ww_quic_config_create(&settings, error, sizeof(error)) == nullptr, "undersized Initial geometry accepted");
    settings                      = Settings(true);
    settings.receive_window_bytes = settings.max_buffered_bytes + 1;
    require(ww_quic_config_create(&settings, error, sizeof(error)) == nullptr, "unbounded receive geometry accepted");
}
} // namespace

int main()
{
    TestConfig();
    TestDeadline();
    TestIdle();
    TestFinalFlush();
    TestRoundtrip(false, "h3");
    TestRoundtrip(true, "waterwall-test");
    TestAdmission();
    TestInvalidOpening();
    TestMissingOpening();
    TestExtraStream(false, false);
    TestExtraStream(false, true);
    TestExtraStream(true, false);
    TestExtraStream(true, true);
    TestCorruptAndIrrelevantPacket();
    TestPartialAckLedger();
    auto cs = Settings(true), ss = Settings(false);
    cs.sni = "wrong.example.test";
    TestFailure("hostname", cs, ss);
    cs         = Settings(true);
    cs.ca_file = nullptr;
    TestFailure("trust", cs, ss);
    cs          = Settings(true);
    cs.protocol = "different-alpn";
    TestFailure("ALPN", cs, ss);
    cs        = Settings(true);
    cs.verify = false;
    cs.sni    = "untrusted.example.test";
    Pair unverified(cs, Settings(false));
    unverified.Handshake();
    std::puts("QUIC engine production tests passed");
    return 0;
}
