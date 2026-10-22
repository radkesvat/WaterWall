#pragma once

/* Private C ABI. No operation calls WaterWall or invokes user callbacks.
 * Handles are confined to their owner's worker; immutable configs may be shared
 * until their last engine has been destroyed. All input bytes are borrowed only
 * for the duration of the call. Events own copies; peek pointers remain valid
 * until consume, close or destroy. No C++ exception crosses this ABI.
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct ww_quic_config ww_quic_config_t;
    typedef struct ww_quic_engine ww_quic_engine_t;

    enum
    {
        WW_QUIC_EVENT_DESCRIPTOR_CHARGE = 24,
        WW_QUIC_SEND_DESCRIPTOR_CHARGE  = 16,
        WW_QUIC_MAX_RECEIVE_WINDOW      = 16777216,
        WW_QUIC_MAX_DATAGRAM            = 1472,
        WW_QUIC_WRITE_CHUNK             = 16384,
        WW_QUIC_MAX_BUFFERED_BYTES      = 67108864,
        WW_QUIC_MAX_BUFFERED_BUFFERS    = 65536,
        WW_QUIC_MAX_TIMEOUT_MS          = 86400000
    };

    typedef struct ww_quic_settings
    {
        bool        is_client;
        bool        verify;
        const char *protocol;
        const char *sni;
        const char *ca_file;
        const char *cert_file;
        const char *key_file;
        uint32_t    handshake_timeout_ms;
        uint32_t    idle_timeout_ms;
        uint32_t    max_packet_size;
        uint32_t    max_buffered_bytes;
        uint32_t    max_buffered_buffers;
        uint32_t    receive_window_bytes;
        /* Fatal-on-OOM repository allocator. Both callbacks are required. */
        void *(*allocate)(size_t);
        void (*deallocate)(void *);
        /* Fatal dependency/allocator failure; must not return. Optional for standalone fixtures. */
        void (*fatal)(void);
    } ww_quic_settings_t;

    typedef enum ww_quic_event_type
    {
        WW_QUIC_EVENT_DATAGRAM,
        WW_QUIC_EVENT_PLAINTEXT,
        WW_QUIC_EVENT_READY,
        WW_QUIC_EVENT_CLOSED
    } ww_quic_event_type_t;

    typedef struct ww_quic_event
    {
        ww_quic_event_type_t type;
        const uint8_t       *data;
        size_t               length;
    } ww_quic_event_t;

    typedef struct ww_quic_storage
    {
        size_t send_bytes; /* Every accepted chunk, including unsent/unacknowledged. */
        size_t send_entries;
        size_t send_allocation;
        size_t wire_bytes;
        size_t wire_entries;
        size_t plaintext_bytes;
        size_t plaintext_entries;
    } ww_quic_storage_t;

    /* Startup validation includes certificate/key matching and trust-bundle parsing.
     * Error strings are written into the supplied bounded caller buffer. */
    ww_quic_config_t *ww_quic_config_create(const ww_quic_settings_t *settings, char *error, size_t error_size);
    void              ww_quic_config_destroy(ww_quic_config_t *config);
    ww_quic_engine_t *ww_quic_engine_create(const ww_quic_config_t *config);
    void              ww_quic_engine_destroy(ww_quic_engine_t *engine);

    /* Start is idempotent. A server waits for a valid v1 Initial before session
     * creation. False indicates terminal failure (and a CLOSED event is staged). */
    bool ww_quic_engine_start(ww_quic_engine_t *engine);
    bool ww_quic_engine_feed(ww_quic_engine_t *engine, const uint8_t *datagram, size_t length);
    /* All-or-nothing copy, at most WW_QUIC_WRITE_CHUNK bytes. False means no input
     * was consumed; inspect closed() to distinguish terminal failure from pressure.
     * Before READY input is refused and remains with the caller. */
    bool ww_quic_engine_write(ww_quic_engine_t *engine, const uint8_t *data, size_t length);
    bool ww_quic_engine_tick(ww_quic_engine_t *engine);
    /* Synchronous best-effort write pump; respects congestion and pacing. */
    bool     ww_quic_engine_flush(ww_quic_engine_t *engine);
    uint64_t ww_quic_now_us(void);
    /* Absolute monotonic microseconds; UINT64_MAX means no pending work. */
    uint64_t    ww_quic_engine_deadline(const ww_quic_engine_t *engine);
    bool        ww_quic_engine_peek(const ww_quic_engine_t *engine, ww_quic_event_t *event);
    void        ww_quic_engine_consume(ww_quic_engine_t *engine);
    void        ww_quic_engine_storage(const ww_quic_engine_t *engine, ww_quic_storage_t *storage);
    bool        ww_quic_engine_ready(const ww_quic_engine_t *engine);
    bool        ww_quic_engine_closed(const ww_quic_engine_t *engine);
    const char *ww_quic_engine_error(const ww_quic_engine_t *engine);
    /* Silent immediate retirement. No final packet/event is generated; all alarms,
     * retained bytes and library state are discarded synchronously. */
    void ww_quic_engine_close(ww_quic_engine_t *engine);

#ifdef __cplusplus
}
#endif
