#include "structure.h"

void realityserverLinestateInitialize(realityserver_lstate_t *ls, buffer_pool_t *pool)
{
    *ls = (realityserver_lstate_t) {
        .read_stream                   = bufferstreamCreate(pool, kRealityServerMaxFramePrefixSize),
        .downstream_tls_observe_stream = bufferstreamCreate(pool, kRealityServerMaxFramePrefixSize),
        .mode                          = kRealityServerModePending,
    };
    realityserverTlsParserInitialize(&ls->client_hello_parser, kRealityServerTlsParserClientHello);
    realityserverTlsParserInitialize(&ls->server_hello_parser, kRealityServerTlsParserServerHello);
    realityserverTls12RecordTrackerInitialize(&ls->client_record_tracker);
    realityserverTls12RecordTrackerInitialize(&ls->server_record_tracker);
    realityserverTlsRecordBoundaryTrackerInitialize(&ls->destination_record_boundary);
}

void realityserverLinestateDestroy(realityserver_lstate_t *ls)
{
    bufferstreamDestroy(&ls->read_stream);
    bufferstreamDestroy(&ls->downstream_tls_observe_stream);
    realityserverTlsParserDestroy(&ls->client_hello_parser);
    realityserverTlsParserDestroy(&ls->server_hello_parser);
    realityserverTls12RecordTrackerDestroy(&ls->client_record_tracker);
    realityserverTls12RecordTrackerDestroy(&ls->server_record_tracker);
    realityserverTlsRecordBoundaryTrackerDestroy(&ls->destination_record_boundary);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
}
