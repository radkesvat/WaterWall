#include "structure.h"

/*
 * Returns:
 *    1  -> looks like an HTTP request (route to web)
 *    0  -> definitely not HTTP (route to tunnel)
 *   -1  -> need more bytes to be sure
 */
int sniffrouterClassify(const uint8_t *p, uint32_t n)
{
    static const char *const methods[] = {"GET ",     "POST ",  "PUT ",     "HEAD ", "DELETE ",
                                           "OPTIONS ", "PATCH ", "TRACE ",   "CONNECT ",
                                           "PRI ", /* HTTP/2 connection preface: "PRI * HTTP/2.0" */
                                           NULL};

    bool any_prefix = false;

    for (int i = 0; methods[i] != NULL; ++i)
    {
        const char *m    = methods[i];
        uint32_t    mlen = (uint32_t) stringLength(m);
        uint32_t    cmp  = n < mlen ? n : mlen;

        if (memoryCompare(p, m, cmp) == 0)
        {
            if (n >= mlen)
            {
                return 1;
            }
            any_prefix = true;
        }
    }

    return any_prefix ? -1 : 0;
}
