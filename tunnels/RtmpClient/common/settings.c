#include "RtmpClient/structure.h"

#include "loggers/network_logger.h"

static bool rtmpValidUrl(const char *url)
{
    const char *authority = NULL;
    if (strncmp(url, "rtmp://", 7) == 0)
        authority = url + 7;
    else if (strncmp(url, "rtmps://", 8) == 0)
        authority = url + 8;
    if (authority == NULL)
    {
        return false;
    }
    const char *path = authority + strcspn(authority, "/?#");
    if (*path != '/' || strcspn(path + 1, "?#") == 0)
    {
        return false;
    }
    for (const unsigned char *p = (const unsigned char *) authority; *p != '\0'; p++)
    {
        if (*p <= ' ' || *p == 127 || strchr("<>\"{}|\\^`", *p) != NULL ||
            (*p == '%' && (! isxdigit(p[1]) || ! isxdigit(p[2]))))
        {
            return false;
        }
    }
    const char *userinfo = memchr(authority, '@', (size_t) (path - authority));
    const char *host     = userinfo == NULL ? authority : userinfo + 1;
    const char *end;
    if (*host == '[')
    {
        const char *bracket = memchr(host, ']', (size_t) (path - host));
        char        literal[INET6_ADDRSTRLEN];
        if (bracket == NULL || (size_t) (bracket - host - 1) >= sizeof(literal))
            return false;
        const size_t length = (size_t) (bracket - host - 1);
        memcpy(literal, host + 1, length);
        literal[length] = '\0';
        struct in6_addr address;
        if (inet_pton(AF_INET6, literal, &address) != 1)
            return false;
        end = bracket + 1;
    }
    else
    {
        end = host + strcspn(host, "/:[]@");
        if (end == host)
            return false;
    }
    if (end == path)
        return true;
    if (*end != ':' || ++end == path)
        return false;
    unsigned port = 0;
    for (; end < path; ++end)
    {
        if (*end < '0' || *end > '9')
            return false;
        port = port * 10U + (unsigned) (*end - '0');
        if (port > UINT16_MAX)
            return false;
    }
    return port != 0;
}

bool rtmpReadClientUrl(node_t *node, rtmp_settings_t *settings)
{
    if (! rtmpReadString(
            node->node_settings_json, "tc-url", NULL, settings->tc_url, sizeof(settings->tc_url), node->type))
        return false;
    if (! rtmpValidUrl(settings->tc_url))
    {
        LOGE("%s: tc-url must be an rtmp:// or rtmps:// application URL", node->type);
        return false;
    }
    return true;
}
