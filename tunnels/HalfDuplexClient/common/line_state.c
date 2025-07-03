#include "structure.h"

#include "loggers/network_logger.h"

void halfduplexclientLinestateInitialize(halfduplexclient_lstate_t *ls, line_t *main_line)
{
    *ls = (halfduplexclient_lstate_t) {.download_line = NULL, .upload_line = NULL, .main_line = main_line,.first_packet_sent = false};
}

void halfduplexclientLinestateDestroy(halfduplexclient_lstate_t *ls)
{
    memorySet(ls, 0, sizeof(halfduplexclient_lstate_t));
}
