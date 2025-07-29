#include "structure.h"

#include "loggers/network_logger.h"

void tlsclientLinestateInitialize(tlsclient_lstate_t *ls, SSL_CTX *sctx)
{

    ls->rbio = BIO_new(BIO_s_mem());
    ls->wbio = BIO_new(BIO_s_mem());
    ls->ssl  = SSL_new(sctx);
    ls->bq   = bufferqueueCreate(2);
}

void tlsclientLinestateDestroy(tlsclient_lstate_t *ls)
{

    SSL_free(ls->ssl); /* free the SSL object and its BIO's */
    BIO_free(ls->rbio);
    BIO_free(ls->wbio);
    bufferqueueDestroy(&(ls->bq));
    memorySet(ls, 0, sizeof(tlsclient_lstate_t));
}
