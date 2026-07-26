#include "wlibc.h"

#if ! defined(OS_WIN)
int main(void)
{
    // Windows-only adapter matching; nothing to test here.
    return 0;
}
#else

#include "wsocket.h"

#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct adapter_fixture
{
    PIP_ADAPTER_ADDRESSES adapters;
    PIP_ADAPTER_ADDRESSES adapter;
    ULONG                 expected_address;
    char                 *friendly_name;
    char                 *lowercase_name;
} adapter_fixture_t;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static PIP_ADAPTER_ADDRESSES enumerateAdapters(void)
{
    ULONG                 size     = 0;
    PIP_ADAPTER_ADDRESSES adapters = NULL;
    ULONG                 result   = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, NULL, &size);

    for (int attempt = 0; attempt < 3 && result == ERROR_BUFFER_OVERFLOW; ++attempt)
    {
        free(adapters);
        adapters = (PIP_ADAPTER_ADDRESSES) malloc(size);
        if (adapters == NULL)
        {
            return NULL;
        }
        result = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, adapters, &size);
    }

    if (result != NO_ERROR)
    {
        free(adapters);
        return NULL;
    }
    return adapters;
}

static char *wideToUtf8(const wchar_t *value)
{
    const int length = WideCharToMultiByte(CP_UTF8, 0, value, -1, NULL, 0, NULL, NULL);
    if (length <= 0)
    {
        return NULL;
    }

    char *utf8 = (char *) malloc((size_t) length);
    if (utf8 == NULL)
    {
        return NULL;
    }
    if (WideCharToMultiByte(CP_UTF8, 0, value, -1, utf8, length, NULL, NULL) <= 0)
    {
        free(utf8);
        return NULL;
    }
    return utf8;
}

static char *lowercaseUtf8(const wchar_t *value)
{
    const int length = LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE, value, -1, NULL, 0, NULL, NULL, 0);
    if (length <= 0)
    {
        return NULL;
    }

    wchar_t *lowercase = (wchar_t *) malloc((size_t) length * sizeof(wchar_t));
    if (lowercase == NULL)
    {
        return NULL;
    }
    if (LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE, value, -1, lowercase, length, NULL, NULL, 0) <= 0)
    {
        free(lowercase);
        return NULL;
    }

    char *utf8 = wideToUtf8(lowercase);
    free(lowercase);
    return utf8;
}

static bool findAdapterFixture(adapter_fixture_t *fixture)
{
    fixture->adapters = enumerateAdapters();
    if (fixture->adapters == NULL)
    {
        return false;
    }

    for (PIP_ADAPTER_ADDRESSES adapter = fixture->adapters; adapter != NULL; adapter = adapter->Next)
    {
        if (adapter->AdapterName == NULL || adapter->FriendlyName == NULL || adapter->FriendlyName[0] == L'\0')
        {
            continue;
        }

        PIP_ADAPTER_UNICAST_ADDRESS address = adapter->FirstUnicastAddress;
        for (; address != NULL; address = address->Next)
        {
            if (address->Address.lpSockaddr == NULL ||
                address->Address.iSockaddrLength < (int) sizeof(struct sockaddr_in) ||
                address->Address.lpSockaddr->sa_family != AF_INET)
            {
                continue;
            }

            char *friendly_name  = wideToUtf8(adapter->FriendlyName);
            char *lowercase_name = lowercaseUtf8(adapter->FriendlyName);
            if (friendly_name == NULL || lowercase_name == NULL)
            {
                free(friendly_name);
                free(lowercase_name);
                continue;
            }

            const struct sockaddr_in *ipv4 = (const struct sockaddr_in *) address->Address.lpSockaddr;
            if (strcmp(friendly_name, lowercase_name) != 0)
            {
                free(fixture->friendly_name);
                free(fixture->lowercase_name);
                fixture->adapter          = adapter;
                fixture->expected_address = ipv4->sin_addr.S_un.S_addr;
                fixture->friendly_name    = friendly_name;
                fixture->lowercase_name   = lowercase_name;
                return true;
            }

            // Keep the first usable adapter as a fallback, but continue looking
            // for one whose lower-case spelling actually exercises insensitive
            // matching.
            if (fixture->adapter == NULL)
            {
                fixture->adapter          = adapter;
                fixture->expected_address = ipv4->sin_addr.S_un.S_addr;
                fixture->friendly_name    = friendly_name;
                fixture->lowercase_name   = lowercase_name;
            }
            else
            {
                free(friendly_name);
                free(lowercase_name);
            }
            break;
        }
    }

    if (fixture->adapter != NULL)
    {
        return true;
    }

    free(fixture->adapters);
    fixture->adapters = NULL;
    return false;
}

static void requireInterfaceAddress(const char *name, ULONG expected_address, const char *failure_message)
{
    ip4_addr_t address = {0};
    require(getInterfaceIp(name, &address, 0), failure_message);
    require(ip4AddrGetU32(&address) == expected_address, "interface name resolved to the wrong adapter address");
}

int main(void)
{
    adapter_fixture_t fixture = {0};
    if (! findAdapterFixture(&fixture))
    {
        printf("SKIP: no Windows adapter with a FriendlyName and IPv4 address was found\n");
        return 0;
    }

    requireInterfaceAddress(
        fixture.friendly_name, fixture.expected_address, "a real adapter FriendlyName must resolve");
    if (strcmp(fixture.friendly_name, fixture.lowercase_name) != 0)
    {
        requireInterfaceAddress(
            fixture.lowercase_name, fixture.expected_address, "a lower-case adapter FriendlyName must resolve");
    }
    else
    {
        printf("NOTE: no discovered adapter FriendlyName changed under lower-casing; "
               "case-insensitive matching was not exercised\n");
    }
    requireInterfaceAddress(
        fixture.adapter->AdapterName, fixture.expected_address, "a real adapter GUID must still resolve");

    ip4_addr_t address = {0};
    require(! getInterfaceIp("waterwall-no-such-interface", &address, 0), "a nonexistent interface name must fail");
    require(! getInterfaceIp("E", &address, 0), "a one-character nonexistent interface name must fail");

    free(fixture.lowercase_name);
    free(fixture.friendly_name);
    free(fixture.adapters);
    return 0;
}

#endif
