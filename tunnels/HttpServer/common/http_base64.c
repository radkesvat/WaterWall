#include "http_base64.h"

bool httpserverBase64UrlDecodeCompat(const char *source, uint8_t *destination, size_t destination_capacity,
                                     size_t *output_length)
{
    if (output_length != NULL)
    {
        *output_length = 0;
    }

    if (source == NULL || destination == NULL || output_length == NULL)
    {
        return false;
    }

    const size_t source_length = stringLength(source);
    if (source_length == SIZE_MAX)
    {
        return false;
    }

    char  *cleaned      = memoryAllocate(source_length + 1U);
    size_t cleaned_size = 0;
    bool   saw_padding  = false;

    for (size_t i = 0; i < source_length; ++i)
    {
        const char c = source[i];
        if (c == ' ' || c == '\t')
        {
            continue;
        }
        if (c == '=')
        {
            saw_padding = true;
            continue;
        }
        if (saw_padding)
        {
            memoryFree(cleaned);
            return false;
        }
        cleaned[cleaned_size++] = c;
    }

    cleaned[cleaned_size] = '\0';
    const bool success    = wwBase64UrlDecode(cleaned, cleaned_size, destination, destination_capacity, output_length);
    memoryFree(cleaned);
    return success;
}
