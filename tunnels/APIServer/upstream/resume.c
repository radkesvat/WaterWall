#include "APIServer/structure.h"

void apiserverUpStreamResume(tunnel_t *t, line_t *line)
{
    apiserver_lstate_t *ls = lineGetState(line, t);
    ls->output_paused      = false;
    apiserverProgress(t, line);
}
