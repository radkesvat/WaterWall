#include "quic_engine.h"

#include <algorithm>
#include <cassert>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "quiche/common/simple_buffer_allocator.h"
#include "quiche/quic/core/crypto/certificate_view.h"
#include "quiche/quic/core/crypto/crypto_handshake_message.h"
#include "quiche/quic/core/crypto/proof_source_x509.h"
#include "quiche/quic/core/crypto/proof_verifier.h"
#include "quiche/quic/core/crypto/quic_compressed_certs_cache.h"
#include "quiche/quic/core/crypto/quic_random.h"
#include "quiche/quic/core/deterministic_connection_id_generator.h"
#include "quiche/quic/core/quic_alarm_factory.h"
#include "quiche/quic/core/quic_clock.h"
#include "quiche/quic/core/quic_constants.h"
#include "quiche/quic/core/quic_crypto_server_stream.h"
#include "quiche/quic/core/quic_framer.h"
#include "quiche/quic/core/quic_generic_session.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/platform/api/quic_flags.h"

extern "C"
{
    extern unsigned char cacert_bytes[];
    extern unsigned int  cacert_len;
}

namespace
{
constexpr size_t  kCredentialLimit    = 4 * 1024 * 1024;
constexpr size_t  kMaxChain           = 32;
constexpr size_t  kAlarmWork          = 32;
constexpr uint8_t kConnectionIdLength = 8;
static_assert(WW_QUIC_MAX_DATAGRAM == quic::kMaxIncomingPacketSize);

[[noreturn]] void Fatal(const ww_quic_settings_t &settings)
{
    if (settings.fatal)
        settings.fatal();
    std::abort();
}

template <typename T> class Allocator
{
  public:
    using value_type = T;
    explicit Allocator(const ww_quic_settings_t &settings) : settings_(&settings) {}
    template <typename U> Allocator(const Allocator<U> &other) : settings_(&other.settings()) {}
    T *allocate(size_t count)
    {
        if (count > SIZE_MAX / sizeof(T))
            Fatal(*settings_);
        void *value = settings_->allocate(count * sizeof(T));
        if (! value)
            Fatal(*settings_);
        return static_cast<T *>(value);
    }
    void                       deallocate(T *value, size_t) { settings_->deallocate(value); }
    const ww_quic_settings_t  &settings() const { return *settings_; }
    template <typename U> bool operator==(const Allocator<U> &other) const { return settings_ == &other.settings(); }
    template <typename U> bool operator!=(const Allocator<U> &other) const { return ! (*this == other); }

  private:
    const ww_quic_settings_t *settings_;
};
template <typename T> class Ring
{
  public:
    Ring(size_t capacity, const ww_quic_settings_t &settings) : items_(Allocator<T>(settings))
    {
        items_.resize(capacity);
    }
    bool   empty() const { return count_ == 0; }
    size_t capacity() const { return items_.size(); }
    T     &front()
    {
        assert(count_);
        return items_[head_];
    }
    const T &front() const
    {
        assert(count_);
        return items_[head_];
    }
    void push_back(T value)
    {
        assert(count_ < items_.size());
        items_[(head_ + count_) % items_.size()] = value;
        ++count_;
    }
    void pop_front()
    {
        assert(count_);
        head_ = (head_ + 1) % items_.size();
        --count_;
    }
    void Release()
    {
        std::vector<T, Allocator<T>> empty(items_.get_allocator());
        items_.swap(empty);
        head_ = count_ = 0;
    }

  private:
    std::vector<T, Allocator<T>> items_;
    size_t                       head_ = 0, count_ = 0;
};

using String       = std::basic_string<char, std::char_traits<char>, Allocator<char>>;
using Certificates = std::vector<String, Allocator<String>>;

// A private allocation header preserves the configured allocator pair for
// library-owned polymorphic bridge adapters, independently of global new/delete.
class RepositoryObject
{
    struct alignas(std::max_align_t) Header
    {
        void (*deallocate)(void *);
    };

  public:
    static void *operator new(size_t size, const ww_quic_settings_t &settings)
    {
        if (size > SIZE_MAX - sizeof(Header))
            Fatal(settings);
        auto *header = static_cast<Header *>(settings.allocate(sizeof(Header) + size));
        if (! header)
            Fatal(settings);
        header->deallocate = settings.deallocate;
        return header + 1;
    }
    static void operator delete(void *value) noexcept
    {
        auto *header = static_cast<Header *>(value) - 1;
        header->deallocate(header);
    }
    static void operator delete(void *value, const ww_quic_settings_t &) noexcept { operator delete(value); }
};
std::vector<std::string> LibraryCertificates(const Certificates &certificates)
{
    std::vector<std::string> result;
    result.reserve(certificates.size());
    for (const auto &cert : certificates)
        result.emplace_back(cert.data(), cert.size());
    return result;
}

void SetError(char *buffer, size_t size, const char *message)
{
    if (buffer != nullptr && size != 0)
        std::snprintf(buffer, size, "%s", message);
}

bool ReadFile(const char *path, String *output)
{
    FILE *file = std::fopen(path, "rb");
    if (file == nullptr)
        return false;
    char chunk[4096];
    while (size_t size = std::fread(chunk, 1, sizeof(chunk), file))
    {
        if (output->size() > kCredentialLimit - size)
        {
            std::fclose(file);
            return false;
        }
        output->append(chunk, size);
    }
    bool success = ! std::ferror(file);
    std::fclose(file);
    return success;
}

bool LoadCertificates(absl::string_view pem, Certificates *der)
{
    bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    if (! bio)
        Fatal(der->get_allocator().settings());
    ERR_clear_error();
    for (;;)
    {
        bssl::UniquePtr<X509> cert(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
        if (! cert)
            break;
        if (der->size() == 4096)
            return false;
        int length = i2d_X509(cert.get(), nullptr);
        if (length <= 0)
            return false;
        String encoded(static_cast<size_t>(length), '\0', Allocator<char>(der->get_allocator().settings()));
        auto  *data = reinterpret_cast<uint8_t *>(encoded.data());
        if (i2d_X509(cert.get(), &data) != length)
            return false;
        der->push_back(std::move(encoded));
    }
    uint32_t error = ERR_peek_last_error();
    bool success = ! der->empty() && ERR_GET_LIB(error) == ERR_LIB_PEM && ERR_GET_REASON(error) == PEM_R_NO_START_LINE;
    ERR_clear_error();
    return success;
}

class Clock final : public quic::QuicClock
{
  public:
    quic::QuicTime     Now() const override { return CreateTimeFromMicroseconds(ww_quic_now_us()); }
    quic::QuicTime     ApproximateNow() const override { return Now(); }
    quic::QuicWallTime WallNow() const override
    {
        auto us =
            std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch())
                .count();
        return quic::QuicWallTime::FromUNIXMicroseconds(static_cast<uint64_t>(us));
    }
};

class AlarmFactory;
class Alarm final : public quic::QuicAlarm, public RepositoryObject
{
  public:
    Alarm(AlarmFactory *factory, quic::QuicArenaScopedPtr<Delegate> delegate);
    ~Alarm() override;
    void Run() { Fire(); }

  private:
    void          SetImpl() override {}
    void          CancelImpl() override {}
    AlarmFactory *factory_;
};

class AlarmFactory final : public quic::QuicAlarmFactory
{
  public:
    quic::QuicAlarm *CreateAlarm(quic::QuicAlarm::Delegate *delegate) override
    {
        return new (alarms.get_allocator().settings())
            Alarm(this, quic::QuicArenaScopedPtr<quic::QuicAlarm::Delegate>(delegate));
    }
    quic::QuicArenaScopedPtr<quic::QuicAlarm> CreateAlarm(quic::QuicArenaScopedPtr<quic::QuicAlarm::Delegate> delegate,
                                                          quic::QuicConnectionArena *) override
    {
        // Heap placement is supported by the arena API; ownership remains with QUICHE.
        return quic::QuicArenaScopedPtr<quic::QuicAlarm>(new (alarms.get_allocator().settings())
                                                             Alarm(this, std::move(delegate)));
    }
    Alarm *Next() const
    {
        Alarm *next = nullptr;
        for (auto *alarm : alarms)
            if (alarm->IsSet() && (next == nullptr || alarm->deadline() < next->deadline()))
                next = alarm;
        return next;
    }
    explicit AlarmFactory(const ww_quic_settings_t &settings) : alarms(Allocator<Alarm *>(settings)) {}
    std::vector<Alarm *, Allocator<Alarm *>> alarms;
};
Alarm::Alarm(AlarmFactory *factory, quic::QuicArenaScopedPtr<Delegate> delegate)
    : QuicAlarm(std::move(delegate)), factory_(factory)
{
    factory_->alarms.push_back(this);
}
Alarm::~Alarm()
{
    std::erase(factory_->alarms, this);
}

class Helper final : public quic::QuicConnectionHelperInterface
{
  public:
    const quic::QuicClock         *GetClock() const override { return &clock; }
    quic::QuicRandom              *GetRandomGenerator() override { return quic::QuicRandom::GetInstance(); }
    quiche::QuicheBufferAllocator *GetStreamSendBufferAllocator() override
    {
        return quiche::SimpleBufferAllocator::Get();
    }
    Clock clock;
};

class VerifyContext final : public quic::ProofVerifyContext, public RepositoryObject
{
};
class Verifier final : public quic::ProofVerifier, public RepositoryObject
{
  public:
    Verifier(bool verify, const Certificates &roots)
        : settings_(roots.get_allocator().settings()), verify_(verify), store_(X509_STORE_new())
    {
        if (! store_)
            Fatal(settings_);
        for (const auto &encoded : roots)
        {
            const auto           *p = reinterpret_cast<const uint8_t *>(encoded.data());
            bssl::UniquePtr<X509> root(d2i_X509(nullptr, &p, static_cast<long>(encoded.size())));
            if (! root || ! X509_STORE_add_cert(store_.get(), root.get()))
                Fatal(settings_); // startup parsed these same immutable roots
        }
    }
    quic::QuicAsyncStatus VerifyProof(const std::string &, uint16_t, const std::string &, quic::QuicTransportVersion,
                                      absl::string_view, const std::vector<std::string> &, const std::string &,
                                      const std::string &, const quic::ProofVerifyContext *, std::string *error,
                                      std::unique_ptr<quic::ProofVerifyDetails> *,
                                      std::unique_ptr<quic::ProofVerifierCallback>) override
    {
        *error = "Legacy QUIC crypto is disabled; QUIC v1 requires TLS 1.3";
        return quic::QUIC_FAILURE;
    }
    quic::QuicAsyncStatus VerifyCertChain(const std::string                    &hostname, uint16_t,
                                          const std::vector<absl::string_view> &certs, const std::string &,
                                          const std::string &, const quic::ProofVerifyContext *, std::string *error,
                                          std::unique_ptr<quic::ProofVerifyDetails> *, uint8_t *alert,
                                          std::unique_ptr<quic::ProofVerifierCallback>) override
    {
        if (! verify_)
            return quic::QUIC_SUCCESS;
        *alert = SSL_AD_BAD_CERTIFICATE;
        if (certs.empty() || certs.size() > kMaxChain)
        {
            *error = "Missing or oversized peer certificate chain";
            return quic::QUIC_FAILURE;
        }
        bssl::UniquePtr<STACK_OF(X509)> chain(sk_X509_new_null());
        bssl::UniquePtr<X509_STORE_CTX> context(X509_STORE_CTX_new());
        if (! chain || ! context)
            Fatal(settings_);
        for (auto encoded : certs)
        {
            const auto           *p = reinterpret_cast<const uint8_t *>(encoded.data());
            bssl::UniquePtr<X509> cert(d2i_X509(nullptr, &p, static_cast<long>(encoded.size())));
            if (! cert || p != reinterpret_cast<const uint8_t *>(encoded.data()) + encoded.size())
            {
                *error = "Malformed peer certificate";
                return quic::QUIC_FAILURE;
            }
            if (! sk_X509_push(chain.get(), cert.get()))
                Fatal(settings_);
            cert.release();
        }
        if (! X509_STORE_CTX_init(context.get(), store_.get(), sk_X509_value(chain.get(), 0), chain.get()))
            Fatal(settings_);
        X509_VERIFY_PARAM *parameters = X509_STORE_CTX_get0_param(context.get());
        X509_VERIFY_PARAM_set_hostflags(parameters, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        if (! X509_VERIFY_PARAM_set1_host(parameters, hostname.data(), hostname.size()) ||
            ! X509_STORE_CTX_set_purpose(context.get(), X509_PURPOSE_SSL_SERVER))
            Fatal(settings_);
        if (X509_verify_cert(context.get()) != 1)
        {
            *error = X509_verify_cert_error_string(X509_STORE_CTX_get_error(context.get()));
            return quic::QUIC_FAILURE;
        }
        return quic::QUIC_SUCCESS;
    }
    std::unique_ptr<quic::ProofVerifyContext> CreateDefaultContext() override
    {
        return std::unique_ptr<VerifyContext>(new (settings_) VerifyContext);
    }

  private:
    const ww_quic_settings_t   &settings_;
    bool                        verify_;
    bssl::UniquePtr<X509_STORE> store_;
};

class ProofHandler final : public quic::QuicCryptoClientStream::ProofHandler
{
    void OnProofValid(const quic::QuicCryptoClientConfig::CachedState &) override {}
    void OnProofVerifyDetailsAvailable(const quic::ProofVerifyDetails &) override {}
    bool OnCertificateRequested(const std::vector<std::string> &) override { return false; }
};
class ServerCryptoHelper final : public quic::QuicCryptoServerStreamBase::Helper
{
    bool CanAcceptClientHello(const quic::CryptoHandshakeMessage &, const quic::QuicSocketAddress &,
                              const quic::QuicSocketAddress &, const quic::QuicSocketAddress &,
                              std::string *) const override
    {
        return true;
    }
};

// Uses the upstream generic stream/session implementation, while enforcing the
// sole application stream before generic session queues can retain extra IDs.
class Session final : public quic::QuicGenericSessionBase, public RepositoryObject
{
  public:
    Session(quic::QuicConnection *connection, const quic::QuicConfig &config, const std::string &alpn,
            const std::string &sni, webtransport::SessionVisitor *visitor, quic::QuicCryptoClientConfig *client_config,
            const quic::QuicCryptoServerConfig *server_config, quic::QuicCompressedCertsCache *cache)
        : QuicGenericSessionBase(connection, true, nullptr, config, alpn, visitor, false, nullptr),
          is_client_(client_config != nullptr)
    {
        // Generic sessions otherwise enable server receive-window auto-tuning up
        // to 24 MiB. Reconstruct the still-unused public controller before
        // Initialize or any stream exists, with an explicitly fixed window.
        auto *controller = flow_controller();
        controller->~QuicFlowController();
        new (controller) quic::QuicFlowController(this,
                                                  quic::QuicUtils::GetInvalidStreamId(connection->transport_version()),
                                                  true,
                                                  0,
                                                  config.GetInitialSessionFlowControlWindowToSend(),
                                                  config.GetInitialSessionFlowControlWindowToSend(),
                                                  false,
                                                  nullptr);
        if (is_client_)
            crypto_ =
                std::make_unique<quic::QuicCryptoClientStream>(quic::QuicServerId(sni, 443),
                                                               this,
                                                               client_config->proof_verifier()->CreateDefaultContext(),
                                                               client_config,
                                                               &proof_handler_,
                                                               false);
        else
            crypto_ = quic::CreateCryptoServerStream(server_config, cache, this, &server_helper_);
    }
    quic::QuicCryptoStream       *GetMutableCryptoStream() override { return crypto_.get(); }
    const quic::QuicCryptoStream *GetCryptoStream() const override { return crypto_.get(); }
    void Connect() { static_cast<quic::QuicCryptoClientStream *>(crypto_.get())->CryptoConnect(); }
    void OnConfigNegotiated() override
    {
        // Google-specific tuning options can alter receive-window geometry.
        // This private raw protocol does not negotiate those extensions.
        if (config()->HasReceivedConnectionOptions() && ! config()->ReceivedConnectionOptions().empty())
        {
            connection()->CloseConnection(quic::QUIC_INVALID_NEGOTIATED_VALUE,
                                          "Google QUIC tuning options are unsupported",
                                          quic::ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
            return;
        }
        QuicGenericSessionBase::OnConfigNegotiated();
        connection()->DisableMtuDiscovery();
    }
    quic::QuicStream *CreateIncomingStream(quic::QuicStreamId id) override
    {
        if (is_client_ || id != 0 || incoming_created_)
        {
            connection()->CloseConnection(quic::QUIC_INVALID_STREAM_ID,
                                          "Only client bidirectional stream 0 is supported",
                                          quic::ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
            return nullptr;
        }
        incoming_created_ = true;
        return QuicGenericSessionBase::CreateIncomingStream(id);
    }

  private:
    bool                                    is_client_;
    bool                                    incoming_created_ = false;
    ProofHandler                            proof_handler_;
    ServerCryptoHelper                      server_helper_;
    std::unique_ptr<quic::QuicCryptoStream> crypto_;
};
} // namespace

struct ww_quic_config
{
    explicit ww_quic_config(const ww_quic_settings_t &s)
        : settings(s), roots(Allocator<String>(settings)), certificates(Allocator<String>(settings))
    {
    }
    ww_quic_settings_t        settings;
    char                      protocol[256]{};
    char                      sni[254]{};
    Certificates              roots;
    Certificates              certificates;
    bssl::UniquePtr<EVP_PKEY> key;
};

struct ww_quic_engine final : webtransport::SessionVisitor
{
    struct Event
    {
        ww_quic_event_type_t type;
        uint8_t             *bytes;
        size_t               length;
    };
    struct Ledger
    {
        uint64_t offset;
        size_t   length;
    };
    static_assert(sizeof(Event) <= WW_QUIC_EVENT_DESCRIPTOR_CHARGE);
    static_assert(sizeof(Ledger) <= WW_QUIC_SEND_DESCRIPTOR_CHARGE);
    class Writer final : public quic::QuicPacketWriter
    {
      public:
        explicit Writer(ww_quic_engine *owner) : owner_(owner) {}
        quic::WriteResult WritePacket(const char *data, size_t length, const quic::QuicIpAddress &,
                                      const quic::QuicSocketAddress &, quic::PerPacketOptions *,
                                      const quic::QuicPacketWriterParams &) override
        {
            if (length > owner_->config->settings.max_packet_size)
                return quic::WriteResult(quic::WRITE_STATUS_MSG_TOO_BIG, EMSGSIZE);
            if (! owner_->Stage(WW_QUIC_EVENT_DATAGRAM, data, length))
                return quic::WriteResult(quic::WRITE_STATUS_ERROR, ENOBUFS);
            return quic::WriteResult(quic::WRITE_STATUS_OK, static_cast<int>(length));
        }
        bool                IsWriteBlocked() const override { return false; }
        void                SetWritable() override {}
        std::optional<int>  MessageTooBigErrorCode() const override { return EMSGSIZE; }
        quic::QuicByteCount GetMaxPacketSize(const quic::QuicSocketAddress &) const override
        {
            return owner_->config->settings.max_packet_size;
        }
        bool                   SupportsReleaseTime() const override { return false; }
        bool                   IsBatchMode() const override { return false; }
        bool                   SupportsEcn() const override { return false; }
        quic::QuicPacketBuffer GetNextWriteLocation(const quic::QuicIpAddress &,
                                                    const quic::QuicSocketAddress &) override
        {
            return {nullptr, nullptr};
        }
        quic::WriteResult Flush() override { return quic::WriteResult(quic::WRITE_STATUS_OK, 0); }

      private:
        ww_quic_engine *owner_;
    };
    class StreamVisitor final : public webtransport::StreamVisitor, public RepositoryObject
    {
      public:
        explicit StreamVisitor(ww_quic_engine *owner) : owner_(owner) {}
        void OnCanRead() override { owner_->Read(); }
        void OnCanWrite() override {}
        void OnResetStreamReceived(webtransport::StreamErrorCode) override { owner_->Fail("Application stream reset"); }
        void OnStopSendingReceived(webtransport::StreamErrorCode) override
        {
            owner_->Fail("Application stream stopped");
        }
        void OnWriteSideInDataRecvdState() override { owner_->Fail("Application stream closed"); }

      private:
        ww_quic_engine *owner_;
    };

    explicit ww_quic_engine(const ww_quic_config *configuration)
        : config(configuration), alarms(configuration->settings), writer(this), generator(kConnectionIdLength),
          cache(16), events(size_t(configuration->settings.max_buffered_buffers) * 2 + 2, configuration->settings),
          ledger(configuration->settings.max_buffered_buffers, configuration->settings), created_us(ww_quic_now_us())
    {
        // Synthetic identities are stable for the borrowed carrier association.
        // They route no traffic and never modify WaterWall's routing metadata.
        auto client             = quic::QuicSocketAddress(quic::QuicIpAddress::Loopback4(), 42424);
        auto server             = quic::QuicSocketAddress(quic::QuicIpAddress::Loopback4(), 443);
        self                    = config->settings.is_client ? client : server;
        peer                    = config->settings.is_client ? server : client;
        storage.send_allocation = ledger.capacity() * WW_QUIC_SEND_DESCRIPTOR_CHARGE;
        wire_allocation         = plaintext_allocation =
            (size_t(config->settings.max_buffered_buffers) + 1) * WW_QUIC_EVENT_DESCRIPTOR_CHARGE;
    }
    ~ww_quic_engine() override { Retire(); }

    bool Stage(ww_quic_event_type_t type, const char *data, size_t length)
    {
        bool    wire       = type == WW_QUIC_EVENT_DATAGRAM;
        size_t &bytes      = wire ? storage.wire_bytes : storage.plaintext_bytes;
        size_t &entries    = wire ? storage.wire_entries : storage.plaintext_entries;
        size_t &allocation = wire ? wire_allocation : plaintext_allocation;
        size_t  limit      = config->settings.max_buffered_bytes;
        size_t  charge     = length;
        if (length > limit - bytes || entries == config->settings.max_buffered_buffers ||
            charge > 2 * limit - allocation)
        {
            Fail(wire ? "QUIC ciphertext staging budget exceeded" : "QUIC plaintext staging budget exceeded");
            return false;
        }
        auto *copy = static_cast<uint8_t *>(config->settings.allocate(length));
        if (copy == nullptr)
            Fatal(config->settings);
        std::memcpy(copy, data, length);
        events.push_back({type, copy, length});
        bytes += length;
        allocation += charge;
        ++entries;
        return true;
    }
    void Fail(absl::string_view reason)
    {
        if (closed)
            return;
        closed = true;
        std::snprintf(
            error, sizeof(error), "%.*s", static_cast<int>(std::min(reason.size(), sizeof(error) - 1)), reason.data());
        events.push_back({WW_QUIC_EVENT_CLOSED, nullptr, 0});
    }
    void Ready()
    {
        if (ready || closed)
            return;
        ready = true;
        events.push_back({WW_QUIC_EVENT_READY, nullptr, 0});
    }
    void OnSessionReady() override { handshake_ready = true; }
    void OnSessionClosed(webtransport::SessionErrorCode, const std::string &message) override
    {
        Fail(message.empty() ? "QUIC connection closed" : message);
    }
    void OnIncomingBidirectionalStreamAvailable() override
    {
        auto *stream = session->AcceptIncomingBidirectionalStream();
        if (stream == nullptr || stream->GetStreamId() != 0 || stream_open)
        {
            Fail("Invalid application stream");
            return;
        }
        stream_open = true;
        stream->SetVisitor(std::unique_ptr<StreamVisitor>(new (config->settings) StreamVisitor(this)));
        Read();
    }
    void OnIncomingUnidirectionalStreamAvailable() override { Fail("Unidirectional application stream refused"); }
    void OnDatagramReceived(absl::string_view) override { Fail("Application datagrams are not supported"); }
    void OnCanCreateNewOutgoingBidirectionalStream() override {}
    void OnCanCreateNewOutgoingUnidirectionalStream() override {}

    webtransport::Stream *Stream() const { return session ? session->GetStreamById(0) : nullptr; }
    void                  Read()
    {
        auto *stream = Stream();
        if (stream == nullptr || closed)
            return;
        // Never release application bytes before the authenticated handshake.
        if (! handshake_ready)
            return;
        char bytes[WW_QUIC_WRITE_CHUNK];
        for (;;)
        {
            auto   result = stream->Read(absl::MakeSpan(bytes));
            size_t offset = 0;
            if (! config->settings.is_client && ! marker_received && result.bytes_read != 0)
            {
                if (bytes[0] != 0)
                {
                    Fail("Invalid QUIC application stream opening byte");
                    return;
                }
                marker_received = true;
                offset          = 1;
                Ready();
            }
            if (result.bytes_read != offset &&
                ! Stage(WW_QUIC_EVENT_PLAINTEXT, bytes + offset, result.bytes_read - offset))
                return;
            if (result.fin)
            {
                Fail("QUIC application stream FIN");
                return;
            }
            if (result.bytes_read == 0)
                return;
        }
    }
    quic::QuicConfig Parameters() const
    {
        quic::QuicConfig result;
        result.SetIdleNetworkTimeout(quic::QuicTime::Delta::FromMilliseconds(config->settings.idle_timeout_ms));
        result.set_max_time_before_crypto_handshake(
            quic::QuicTime::Delta::FromMilliseconds(config->settings.handshake_timeout_ms));
        result.set_max_idle_time_before_crypto_handshake(
            quic::QuicTime::Delta::FromMilliseconds(config->settings.handshake_timeout_ms));
        result.SetMaxBidirectionalStreamsToSend(config->settings.is_client ? 0 : 1);
        result.SetMaxUnidirectionalStreamsToSend(0);
        result.SetMaxDatagramFrameSizeToSend(0);
        result.SetMaxPacketSizeToSend(WW_QUIC_MAX_DATAGRAM);
        result.SetInitialStreamFlowControlWindowToSend(config->settings.receive_window_bytes);
        result.SetInitialSessionFlowControlWindowToSend(config->settings.receive_window_bytes);
        result.set_max_undecryptable_packets(8);
        result.SetDisableConnectionMigration();
        result.SetActiveConnectionIdLimitToSend(2);
        return result;
    }
    void Create(quic::QuicConnectionId id)
    {
        auto *connection = new quic::QuicConnection(id,
                                                    self,
                                                    peer,
                                                    &helper,
                                                    &alarms,
                                                    &writer,
                                                    false,
                                                    config->settings.is_client ? quic::Perspective::IS_CLIENT
                                                                               : quic::Perspective::IS_SERVER,
                                                    quic::GetQuicVersionsForGenericSession(),
                                                    generator);
        connection->SetMaxPacketLength(config->settings.max_packet_size);
        if (config->settings.is_client)
        {
            client_crypto = std::make_unique<quic::QuicCryptoClientConfig>(
                std::unique_ptr<Verifier>(new (config->settings) Verifier(config->settings.verify, config->roots)));
            SSL_CTX_set_early_data_enabled(client_crypto->ssl_ctx(), 0);
        }
        else
        {
            EVP_PKEY_up_ref(config->key.get());
            auto proof = quic::ProofSourceX509::Create(
                quiche::QuicheReferenceCountedPointer<quic::ProofSource::Chain>(
                    new quic::ProofSource::Chain(LibraryCertificates(config->certificates))),
                quic::CertificatePrivateKey(bssl::UniquePtr<EVP_PKEY>(config->key.get())));
            if (! proof)
                Fatal(config->settings);
            char secret[32];
            quic::QuicRandom::GetInstance()->RandBytes(secret, sizeof(secret));
            server_crypto = std::make_unique<quic::QuicCryptoServerConfig>(absl::string_view(secret, sizeof(secret)),
                                                                           quic::QuicRandom::GetInstance(),
                                                                           std::move(proof),
                                                                           quic::KeyExchangeSource::Default());
            SSL_CTX_set_early_data_enabled(server_crypto->ssl_ctx(), 0);
            SSL_CTX_set_num_tickets(server_crypto->ssl_ctx(), 0);
        }
        session.reset(new (config->settings) Session(connection,
                                                     Parameters(),
                                                     config->protocol,
                                                     config->sni,
                                                     this,
                                                     client_crypto.get(),
                                                     server_crypto.get(),
                                                     &cache));
        session->Initialize();
        connection->DisableMtuDiscovery();
    }
    bool Bootstrap(const uint8_t *bytes, size_t length)
    {
        quic::QuicEncryptedPacket        packet(reinterpret_cast<const char *>(bytes), length);
        quic::PacketHeaderFormat         format;
        quic::QuicLongHeaderType         type;
        bool                             version_present, length_prefix;
        quic::QuicVersionLabel           label;
        quic::ParsedQuicVersion          version = quic::ParsedQuicVersion::Unsupported();
        absl::string_view                destination, source;
        std::optional<absl::string_view> token;
        std::string                      diagnostic;
        auto                             result = quic::QuicFramer::ParsePublicHeaderDispatcher(packet,
                                                                    kConnectionIdLength,
                                                                    &format,
                                                                    &type,
                                                                    &version_present,
                                                                    &length_prefix,
                                                                    &label,
                                                                    &version,
                                                                    &destination,
                                                                    &source,
                                                                    &token,
                                                                    &diagnostic);
        if (result != quic::QUIC_NO_ERROR || ! version_present || version != quic::ParsedQuicVersion::RFCv1() ||
            type != quic::INITIAL || length < 1200 || destination.size() < 8 || destination.size() > 20)
            return false; // irrelevant traffic is dropped without creating session state
        Create(quic::QuicConnectionId(destination.data(), destination.size()));
        // The connection starts with the peer's actual original destination CID;
        // QUICHE initializes Initial keys and server transport parameters from it.
        return true;
    }
    bool AcceptServerDestination(const uint8_t *bytes, size_t length) const
    {
        auto *connection = session->connection();
        auto  matches    = [bytes, length](const quic::QuicConnectionId &id) {
            quic::QuicEncryptedPacket        packet(reinterpret_cast<const char *>(bytes), length);
            quic::PacketHeaderFormat         format;
            quic::QuicLongHeaderType         type;
            bool                             version_present, length_prefix;
            quic::QuicVersionLabel           label;
            quic::ParsedQuicVersion          version = quic::ParsedQuicVersion::Unsupported();
            absl::string_view                destination, source;
            std::optional<absl::string_view> token;
            std::string                      diagnostic;
            return quic::QuicFramer::ParsePublicHeaderDispatcher(packet,
                                                                 id.length(),
                                                                 &format,
                                                                 &type,
                                                                 &version_present,
                                                                 &length_prefix,
                                                                 &label,
                                                                 &version,
                                                                 &destination,
                                                                 &source,
                                                                 &token,
                                                                 &diagnostic) == quic::QUIC_NO_ERROR &&
                   destination == absl::string_view(id.data(), id.length());
        };
        // A dispatcher normally filters foreign CIDs before the server connection;
        // QUICHE assumes that contract and asserts on an unexpected server CID.
        // Keep the current CID path allocation-free, and accept unretired rotations
        // and the original destination CID through the public connection registry.
        if (matches(connection->connection_id()))
            return true;
        for (const auto &id : connection->GetActiveServerConnectionIds())
            if (id != connection->connection_id() && matches(id))
                return true;
        return false;
    }
    void Reap()
    {
        if (ledger.empty() || closed || ! session)
            return;
        auto *stream = session->GetActiveStream(0);
        if (stream == nullptr)
        {
            Fail("Application stream disappeared with retained send data");
            return;
        }
        while (! ledger.empty())
        {
            const auto &entry = ledger.front();
            if (stream->IsStreamFrameOutstanding(entry.offset, entry.length, false))
                break;
            storage.send_bytes -= entry.length;
            storage.send_allocation -= entry.length;
            --storage.send_entries;
            ledger.pop_front();
        }
    }
    bool Write(const uint8_t *bytes, size_t length)
    {
        auto *stream = Stream();
        if (! stream || ! stream->CanWrite() || closed)
            return false;
        size_t             limit                 = config->settings.max_buffered_bytes;
        constexpr uint64_t maximum_stream_offset = (UINT64_C(1) << 62) - 1;
        if (length > maximum_stream_offset - send_offset)
        {
            Fail("QUIC application stream offset exhausted");
            return false;
        }
        if (length > limit - storage.send_bytes || storage.send_entries == config->settings.max_buffered_buffers ||
            length > 2 * limit - storage.send_allocation)
            return false;
        auto *copy = static_cast<char *>(config->settings.allocate(length));
        if (! copy)
            Fatal(config->settings);
        std::memcpy(copy, bytes, length);
        auto                   release = config->settings.deallocate;
        quiche::QuicheMemSlice slice(
            copy, length, [release](absl::string_view value) { release(const_cast<char *>(value.data())); });
        absl::Status status = stream->Writev(absl::MakeSpan(&slice, 1), {});
        if (! status.ok())
        {
            if (status.code() != absl::StatusCode::kUnavailable)
                Fail(status.message());
            return false;
        }
        ledger.push_back({send_offset, length});
        send_offset += length;
        storage.send_bytes += length;
        storage.send_allocation += length;
        ++storage.send_entries;
        return true;
    }
    bool AfterDrive()
    {
        if (! closed && handshake_ready && config->settings.is_client)
        {
            if (! stream_open && session->CanOpenNextOutgoingBidirectionalStream())
            {
                auto *stream = session->OpenOutgoingBidirectionalStream();
                if (stream == nullptr || stream->GetStreamId() != 0)
                    Fail("Cannot open sole QUIC application stream");
                else
                {
                    stream_open = true;
                    stream->SetVisitor(std::unique_ptr<StreamVisitor>(new (config->settings) StreamVisitor(this)));
                }
            }
            if (stream_open && ! marker_sent)
            {
                const uint8_t marker = 0;
                if (Write(&marker, 1))
                {
                    marker_sent = true;
                    Ready();
                }
            }
        }
        if (! closed && handshake_ready && stream_open)
            Read();
        Reap();
        if (! closed && ! ready &&
            ww_quic_now_us() - created_us >= uint64_t(config->settings.handshake_timeout_ms) * 1000)
            Fail("QUIC handshake/stream-opening deadline exceeded");
        return ! closed;
    }
    void Retire()
    {
        // session destruction cancels all its alarms before their registry dies.
        session.reset();
        client_crypto.reset();
        server_crypto.reset();
        while (! events.empty())
        {
            if (events.front().bytes)
                config->settings.deallocate(events.front().bytes);
            events.pop_front();
        }
        events.Release();
        ledger.Release();
        storage         = {};
        wire_allocation = plaintext_allocation = 0;
        closed                                 = true;
    }

    const ww_quic_config                         *config;
    Helper                                        helper;
    AlarmFactory                                  alarms;
    Writer                                        writer;
    quic::DeterministicConnectionIdGenerator      generator;
    quic::QuicCompressedCertsCache                cache;
    quic::QuicSocketAddress                       self, peer;
    std::unique_ptr<quic::QuicCryptoClientConfig> client_crypto;
    std::unique_ptr<quic::QuicCryptoServerConfig> server_crypto;
    std::unique_ptr<Session>                      session;
    Ring<Event>                                   events;
    Ring<Ledger>                                  ledger;
    ww_quic_storage_t                             storage{};
    size_t                                        wire_allocation = 0, plaintext_allocation = 0;
    uint64_t                                      created_us;
    uint64_t                                      send_offset = 0;
    char                                          error[512]{};
    bool                                          started         = false;
    bool                                          handshake_ready = false;
    bool                                          stream_open     = false;
    bool                                          marker_received = false;
    bool                                          marker_sent     = false;
    bool                                          ready           = false;
    bool                                          closed          = false;
};

extern "C" uint64_t ww_quic_now_us(void)
{
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch())
            .count());
}

extern "C" ww_quic_config_t *ww_quic_config_create(const ww_quic_settings_t *settings, char *error, size_t error_size)
try
{
    assert(settings && settings->allocate && settings->deallocate);
    static std::once_flag flags_once;
    std::call_once(flags_once, [] {
        SetQuicFlag(quic_bounded_crypto_send_buffer, true);
        SetQuicFlag(quic_enforce_strict_amplification_factor, true);
    });
    const auto &s = *settings;
    if (! s.protocol || std::strlen(s.protocol) < 1 || std::strlen(s.protocol) > 255 ||
        ! std::all_of(
            s.protocol, s.protocol + std::strlen(s.protocol), [](unsigned char c) { return c >= 32 && c <= 126; }))
    {
        SetError(error, error_size, "protocol must contain 1..255 printable ASCII bytes");
        return nullptr;
    }
    if (s.handshake_timeout_ms == 0 || s.handshake_timeout_ms > WW_QUIC_MAX_TIMEOUT_MS || s.idle_timeout_ms == 0 ||
        s.idle_timeout_ms > WW_QUIC_MAX_TIMEOUT_MS || s.max_packet_size < 1200 || s.max_packet_size > 1452 ||
        s.max_buffered_bytes < s.max_packet_size || s.max_buffered_bytes > WW_QUIC_MAX_BUFFERED_BYTES ||
        s.max_buffered_buffers == 0 || s.max_buffered_buffers > WW_QUIC_MAX_BUFFERED_BUFFERS ||
        s.receive_window_bytes < 16384 || s.receive_window_bytes > s.max_buffered_bytes ||
        s.receive_window_bytes > WW_QUIC_MAX_RECEIVE_WINDOW)
    {
        SetError(error,
                 error_size,
                 "invalid QUIC timeout, max-packet-size (1200..1452), queue, or receive-window-bytes geometry");
        return nullptr;
    }
    if ((size_t(s.max_buffered_buffers) + 1) * WW_QUIC_EVENT_DESCRIPTOR_CHARGE > s.max_buffered_bytes)
    {
        SetError(error, error_size, "max-buffered-buffers descriptor storage exceeds max-buffered-bytes");
        return nullptr;
    }
    if (s.is_client)
    {
        if (! s.sni || std::strlen(s.sni) == 0 || std::strlen(s.sni) > 253)
        {
            SetError(error, error_size, "sni must be an ASCII DNS name of 1..253 bytes");
            return nullptr;
        }
        size_t label = 0;
        for (const char *p = s.sni; *p; ++p)
        {
            unsigned char c = static_cast<unsigned char>(*p);
            if (c == '.')
            {
                if (label == 0 || label > 63 || p[-1] == '-')
                {
                    SetError(error, error_size, "sni contains an invalid DNS label");
                    return nullptr;
                }
                label = 0;
            }
            else if (((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') &&
                     ! (label == 0 && c == '-'))
                ++label;
            else
            {
                SetError(error, error_size, "sni must use ASCII DNS labels or A-label/punycode");
                return nullptr;
            }
        }
        if (label == 0 || label > 63 || s.sni[std::strlen(s.sni) - 1] == '-')
        {
            SetError(error, error_size, "sni contains an invalid final DNS label");
            return nullptr;
        }
    }
    void *memory = s.allocate(sizeof(ww_quic_config));
    if (! memory)
        Fatal(*settings);
    auto deleter = [&s](ww_quic_config *p) {
        p->~ww_quic_config();
        s.deallocate(p);
    };
    std::unique_ptr<ww_quic_config, decltype(deleter)> config(new (memory) ww_quic_config(s), deleter);
    std::snprintf(config->protocol, sizeof(config->protocol), "%s", s.protocol);
    std::snprintf(config->sni, sizeof(config->sni), "%s", s.sni ? s.sni : "");
    if (s.is_client && s.verify)
    {
        String pem(Allocator<char>(config->settings));
        if (s.ca_file ? ! ReadFile(s.ca_file, &pem) : false)
        {
            SetError(error, error_size, "cannot read ca-file (maximum 4 MiB)");
            return nullptr;
        }
        if (! s.ca_file)
            pem.assign(reinterpret_cast<const char *>(cacert_bytes), cacert_len);
        if (! LoadCertificates(absl::string_view(pem.data(), pem.size()), &config->roots))
        {
            SetError(error, error_size, "ca-file: malformed or empty CA certificate bundle");
            return nullptr;
        }
    }
    if (! s.is_client)
    {
        String cert(Allocator<char>(config->settings)), key(Allocator<char>(config->settings));
        if (! s.cert_file || ! s.key_file || ! ReadFile(s.cert_file, &cert) || ! ReadFile(s.key_file, &key))
        {
            SetError(error, error_size, "cannot read cert-file/key-file (maximum 4 MiB each)");
            return nullptr;
        }
        if (! LoadCertificates(absl::string_view(cert.data(), cert.size()), &config->certificates) ||
            config->certificates.size() > kMaxChain)
        {
            SetError(error, error_size, "cert-file: malformed certificate chain (maximum 32 certificates)");
            return nullptr;
        }
        bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(key.data(), static_cast<int>(key.size())));
        if (! bio)
            Fatal(*settings);
        config->key.reset(
            PEM_read_bio_PrivateKey(bio.get(), nullptr, +[](char *, int, int, void *) { return 0; }, nullptr));
        auto leaf = quic::CertificateView::ParseSingleCertificate(
            absl::string_view(config->certificates.front().data(), config->certificates.front().size()));
        if (! config->key || ! leaf)
        {
            SetError(error, error_size, "key-file/cert-file: malformed QUIC server key or leaf certificate");
            return nullptr;
        }
        EVP_PKEY_up_ref(config->key.get());
        quic::CertificatePrivateKey candidate(bssl::UniquePtr<EVP_PKEY>(config->key.get()));
        if (! candidate.MatchesPublicKey(*leaf))
        {
            SetError(error, error_size, "key-file: QUIC server private key does not match cert-file leaf certificate");
            return nullptr;
        }
        auto proof =
            quic::ProofSourceX509::Create(quiche::QuicheReferenceCountedPointer<quic::ProofSource::Chain>(
                                              new quic::ProofSource::Chain(LibraryCertificates(config->certificates))),
                                          std::move(candidate));
        if (! proof)
        {
            SetError(error, error_size, "cert-file: QUIC server certificate is unsupported by the X509 proof source");
            return nullptr;
        }
    }
    return config.release();
}
catch (...)
{
    Fatal(*settings);
}

extern "C" void ww_quic_config_destroy(ww_quic_config_t *config)
{
    if (! config)
        return;
    auto release = config->settings.deallocate;
    config->~ww_quic_config();
    release(config);
}
extern "C" ww_quic_engine_t *ww_quic_engine_create(const ww_quic_config_t *config)
try
{
    assert(config);
    void *memory = config->settings.allocate(sizeof(ww_quic_engine));
    if (! memory)
        Fatal(config->settings);
    return new (memory) ww_quic_engine(config);
}
catch (...)
{
    Fatal(config->settings);
}
extern "C" void ww_quic_engine_destroy(ww_quic_engine_t *engine)
{
    if (! engine)
        return;
    auto release = engine->config->settings.deallocate;
    engine->~ww_quic_engine();
    release(engine);
}
extern "C" bool ww_quic_engine_start(ww_quic_engine_t *engine)
try
{
    assert(engine);
    if (! engine->started && ! engine->closed)
    {
        engine->started = true;
        if (engine->config->settings.is_client)
        {
            char id[kConnectionIdLength];
            quic::QuicRandom::GetInstance()->RandBytes(id, sizeof(id));
            engine->Create(quic::QuicConnectionId(id, sizeof(id)));
            engine->session->Connect();
        }
    }
    return engine->AfterDrive();
}
catch (...)
{
    Fatal(engine->config->settings);
}
extern "C" bool ww_quic_engine_feed(ww_quic_engine_t *engine, const uint8_t *datagram, size_t length)
try
{
    assert(engine && (datagram || length == 0));
    if (engine->closed)
        return false;
    if (length == 0 || length > WW_QUIC_MAX_DATAGRAM)
        return engine->AfterDrive(); // invalid UDP traffic is dropped, without unchecked allocation
    if (! engine->session && ! engine->config->settings.is_client && ! engine->Bootstrap(datagram, length))
        return engine->AfterDrive();
    if (! engine->session)
        return engine->AfterDrive();
    if (! engine->config->settings.is_client && ! engine->AcceptServerDestination(datagram, length))
        return engine->AfterDrive();
    quic::QuicReceivedPacket packet(reinterpret_cast<const char *>(datagram), length, engine->helper.clock.Now());
    engine->session->connection()->ProcessUdpPacket(engine->self, engine->peer, packet);
    return engine->AfterDrive();
}
catch (...)
{
    Fatal(engine->config->settings);
}
extern "C" bool ww_quic_engine_write(ww_quic_engine_t *engine, const uint8_t *data, size_t length)
try
{
    assert(engine && (data || length == 0) && length <= WW_QUIC_WRITE_CHUNK);
    if (! engine->ready || engine->closed)
        return false;
    if (length == 0)
        return true;
    bool result = engine->Write(data, length);
    engine->AfterDrive();
    return result;
}
catch (...)
{
    Fatal(engine->config->settings);
}
extern "C" bool ww_quic_engine_tick(ww_quic_engine_t *engine)
try
{
    assert(engine);
    if (engine->closed)
        return false;
    for (size_t work = 0; work < kAlarmWork; ++work)
    {
        Alarm *alarm = engine->alarms.Next();
        if (! alarm || alarm->deadline() > engine->helper.clock.Now())
            break;
        alarm->Run();
        if (engine->closed)
            break;
    }
    return engine->AfterDrive();
}
catch (...)
{
    Fatal(engine->config->settings);
}
extern "C" bool ww_quic_engine_flush(ww_quic_engine_t *engine)
try
{
    assert(engine);
    if (engine->closed)
        return false;
    if (engine->session)
        engine->session->connection()->OnCanWrite();
    return engine->AfterDrive();
}
catch (...)
{
    Fatal(engine->config->settings);
}
extern "C" uint64_t ww_quic_engine_deadline(const ww_quic_engine_t *engine)
{
    assert(engine);
    if (engine->closed)
        return UINT64_MAX;
    uint64_t deadline = engine->ready
                            ? UINT64_MAX
                            : engine->created_us + uint64_t(engine->config->settings.handshake_timeout_ms) * 1000;
    if (Alarm *alarm = engine->alarms.Next())
        deadline = std::min(deadline, static_cast<uint64_t>(alarm->deadline().ToDebuggingValue()));
    return deadline;
}
extern "C" bool ww_quic_engine_peek(const ww_quic_engine_t *engine, ww_quic_event_t *event)
{
    assert(engine && event);
    if (engine->events.empty())
        return false;
    const auto &front = engine->events.front();
    *event            = {front.type, front.bytes, front.length};
    return true;
}
extern "C" void ww_quic_engine_consume(ww_quic_engine_t *engine)
{
    assert(engine && ! engine->events.empty());
    const auto &front = engine->events.front();
    if (front.bytes)
    {
        bool wire = front.type == WW_QUIC_EVENT_DATAGRAM;
        (wire ? engine->storage.wire_bytes : engine->storage.plaintext_bytes) -= front.length;
        --(wire ? engine->storage.wire_entries : engine->storage.plaintext_entries);
        (wire ? engine->wire_allocation : engine->plaintext_allocation) -= front.length;
        engine->config->settings.deallocate(front.bytes);
    }
    engine->events.pop_front();
}
extern "C" void ww_quic_engine_storage(const ww_quic_engine_t *engine, ww_quic_storage_t *storage)
{
    assert(engine && storage);
    *storage = engine->storage;
}
extern "C" bool ww_quic_engine_ready(const ww_quic_engine_t *engine)
{
    return engine->ready && ! engine->closed;
}
extern "C" bool ww_quic_engine_closed(const ww_quic_engine_t *engine)
{
    return engine->closed;
}
extern "C" const char *ww_quic_engine_error(const ww_quic_engine_t *engine)
{
    return engine->error;
}
extern "C" void ww_quic_engine_close(ww_quic_engine_t *engine)
{
    engine->Retire();
}
