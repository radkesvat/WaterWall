#include "structure.h"

#include "loggers/network_logger.h"

void tlsclientPrintSSLState(const SSL *ssl)
{
    const char *current_state = SSL_state_string_long(ssl);
    LOGD("TlsClient: BoringSSL State: %s", current_state);
}

void tlsclientPrintSSLError(void)
{
    BIO *bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);
    char *buf = NULL;
    size_t len = BIO_get_mem_data(bio, &buf);
    if (len > 0)
    {
        LOGE("TlsClient: BoringSSL Error: %.*s", len, buf);
    }
    BIO_free(bio);
}
void tlsclientPrintSSLErrorAndAbort(void)
{
    tlsclientPrintSSLError();
    abort();
}

