#include "base64.h"

/* BASE 64 encode table */
static const char base64en[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
    'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
    's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/',
};

#define BASE64_PAD     '='
#define BASE64DE_FIRST '+'
#define BASE64DE_LAST  'z'
/* ASCII order for BASE 64 decode, -1 in unused character */
static const signed char base64de[] = {
    /* '+', ',', '-', '.', '/', '0', '1', '2', */
    62,
    -1,
    -1,
    -1,
    63,
    52,
    53,
    54,

    /* '3', '4', '5', '6', '7', '8', '9', ':', */
    55,
    56,
    57,
    58,
    59,
    60,
    61,
    -1,

    /* ';', '<', '=', '>', '?', '@', 'A', 'B', */
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    0,
    1,

    /* 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', */
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,

    /* 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', */
    10,
    11,
    12,
    13,
    14,
    15,
    16,
    17,

    /* 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', */
    18,
    19,
    20,
    21,
    22,
    23,
    24,
    25,

    /* '[', '\', ']', '^', '_', '`', 'a', 'b', */
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    26,
    27,

    /* 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', */
    28,
    29,
    30,
    31,
    32,
    33,
    34,
    35,

    /* 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', */
    36,
    37,
    38,
    39,
    40,
    41,
    42,
    43,

    /* 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', */
    44,
    45,
    46,
    47,
    48,
    49,
    50,
    51,
};

int wwBase64Encode(const unsigned char *in, unsigned int inlen, char *out)
{
    unsigned int i = 0, j = 0;

    if (inlen == 0)
    {
        return 0;
    }

    for (; i < inlen; i++)
    {
        int s = (int) (i % 3);

        switch (s)
        {
        case 0:
            out[j++] = base64en[(in[i] >> 2) & 0x3F];
            continue;
        case 1:
            out[j++] = base64en[((in[i - 1] & 0x3) << 4) + ((in[i] >> 4) & 0xF)];
            continue;
        case 2:
            out[j++] = base64en[((in[i - 1] & 0xF) << 2) + ((in[i] >> 6) & 0x3)];
            out[j++] = base64en[in[i] & 0x3F];
        }
    }

    /* move back */
    i -= 1;

    /* check the last and add padding */
    if ((i % 3) == 0)
    {
        out[j++] = base64en[(in[i] & 0x3) << 4];
        out[j++] = BASE64_PAD;
        out[j++] = BASE64_PAD;
    }
    else if ((i % 3) == 1)
    {
        out[j++] = base64en[(in[i] & 0xF) << 2];
        out[j++] = BASE64_PAD;
    }

    return (int) (j);
}

int wwBase64Decode(const char *in, unsigned int inlen, unsigned char *out)
{
    unsigned int i = 0, j = 0;

    if ((inlen % 4) != 0)
    {
        return -1;
    }

    for (; i < inlen; i += 4)
    {
        int           c0, c1, c2, c3;
        unsigned char ch0 = (unsigned char) in[i];
        unsigned char ch1 = (unsigned char) in[i + 1];
        unsigned char ch2 = (unsigned char) in[i + 2];
        unsigned char ch3 = (unsigned char) in[i + 3];

        if (ch0 < BASE64DE_FIRST || ch0 > BASE64DE_LAST || (c0 = base64de[ch0 - BASE64DE_FIRST]) == -1)
        {
            return -1;
        }
        if (ch1 < BASE64DE_FIRST || ch1 > BASE64DE_LAST || (c1 = base64de[ch1 - BASE64DE_FIRST]) == -1)
        {
            return -1;
        }

        if (ch2 == BASE64_PAD)
        {
            /* xx== is only valid in the final 4-char block */
            if (ch3 != BASE64_PAD || (i + 4) != inlen)
            {
                return -1;
            }
            out[j++] = (unsigned char) (((unsigned int) c0 << 2) | (((unsigned int) c1 >> 4) & 0x3));
            return (int) j;
        }

        if (ch2 < BASE64DE_FIRST || ch2 > BASE64DE_LAST || (c2 = base64de[ch2 - BASE64DE_FIRST]) == -1)
        {
            return -1;
        }

        if (ch3 == BASE64_PAD)
        {
            /* xxx= is only valid in the final 4-char block */
            if ((i + 4) != inlen)
            {
                return -1;
            }
            out[j++] = (unsigned char) (((unsigned int) c0 << 2) | (((unsigned int) c1 >> 4) & 0x3));
            out[j++] = (unsigned char) ((((unsigned int) c1 & 0xF) << 4) | (((unsigned int) c2 >> 2) & 0xF));
            return (int) j;
        }

        if (ch3 < BASE64DE_FIRST || ch3 > BASE64DE_LAST || (c3 = base64de[ch3 - BASE64DE_FIRST]) == -1)
        {
            return -1;
        }

        out[j++] = (unsigned char) (((unsigned int) c0 << 2) | (((unsigned int) c1 >> 4) & 0x3));
        out[j++] = (unsigned char) ((((unsigned int) c1 & 0xF) << 4) | (((unsigned int) c2 >> 2) & 0xF));
        out[j++] = (unsigned char) ((((unsigned int) c2 & 0x3) << 6) | (unsigned int) c3);
    }

    return (int) (j);
}

bool wwBase64UrlEncodedSizeNoPadding(size_t input_len, size_t *output_len)
{
    if (output_len == NULL)
    {
        return false;
    }

    size_t full_groups = input_len / 3U;
    size_t rem         = input_len % 3U;
    size_t rem_bytes   = (rem == 0U ? 0U : (rem == 1U ? 2U : 3U));

    if (full_groups > (SIZE_MAX - rem_bytes) / 4U)
    {
        return false;
    }

    *output_len = full_groups * 4U + rem_bytes;
    return true;
}

bool wwBase64UrlEncodeNoPadding(const uint8_t *input, size_t input_len, char *output, size_t output_capacity,
                                size_t *output_len)
{
    static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    if (output_len != NULL)
    {
        *output_len = 0;
    }

    if ((input_len > 0U && input == NULL) || output == NULL)
    {
        return false;
    }

    size_t req_len = 0;
    if (! wwBase64UrlEncodedSizeNoPadding(input_len, &req_len))
    {
        return false;
    }

    if (output_capacity < req_len)
    {
        return false;
    }

    size_t out_pos = 0;
    size_t i       = 0;

    while (i + 3U <= input_len)
    {
        uint32_t v        = ((uint32_t) input[i] << 16) | ((uint32_t) input[i + 1] << 8) | ((uint32_t) input[i + 2]);
        output[out_pos++] = table[(v >> 18) & 0x3F];
        output[out_pos++] = table[(v >> 12) & 0x3F];
        output[out_pos++] = table[(v >> 6) & 0x3F];
        output[out_pos++] = table[v & 0x3F];
        i += 3U;
    }

    size_t rem = input_len - i;
    if (rem == 1U)
    {
        uint32_t v        = ((uint32_t) input[i] << 16);
        output[out_pos++] = table[(v >> 18) & 0x3F];
        output[out_pos++] = table[(v >> 12) & 0x3F];
    }
    else if (rem == 2U)
    {
        uint32_t v        = ((uint32_t) input[i] << 16) | ((uint32_t) input[i + 1] << 8);
        output[out_pos++] = table[(v >> 18) & 0x3F];
        output[out_pos++] = table[(v >> 12) & 0x3F];
        output[out_pos++] = table[(v >> 6) & 0x3F];
    }

    if (output_capacity > req_len)
    {
        output[req_len] = '\0';
    }

    if (output_len != NULL)
    {
        *output_len = req_len;
    }

    return true;
}

static inline int base64UrlCharValue(char c)
{
    if (c >= 'A' && c <= 'Z')
    {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z')
    {
        return 26 + (c - 'a');
    }
    if (c >= '0' && c <= '9')
    {
        return 52 + (c - '0');
    }
    if (c == '-')
    {
        return 62;
    }
    if (c == '_')
    {
        return 63;
    }
    return -1;
}

bool wwBase64UrlDecode(const char *input, size_t input_len, uint8_t *output, size_t output_capacity, size_t *output_len)
{
    if (output_len != NULL)
    {
        *output_len = 0;
    }

    if ((input_len > 0U && input == NULL) || output == NULL)
    {
        return false;
    }

    if (input_len == 0U)
    {
        return true;
    }

    size_t pad_count = 0;
    while (pad_count < input_len && input[input_len - 1U - pad_count] == '=')
    {
        pad_count++;
    }

    if (pad_count > 2U)
    {
        return false;
    }

    size_t effective_len = input_len - pad_count;
    for (size_t i = 0; i < effective_len; ++i)
    {
        if (input[i] == '=')
        {
            return false;
        }
    }

    if (pad_count > 0U)
    {
        if ((effective_len + pad_count) % 4U != 0U)
        {
            return false;
        }
        if (pad_count == 1U && effective_len % 4U != 3U)
        {
            return false;
        }
        if (pad_count == 2U && effective_len % 4U != 2U)
        {
            return false;
        }
    }

    size_t rem = effective_len % 4U;
    if (rem == 1U)
    {
        return false;
    }

    size_t full_blocks = effective_len / 4U;
    size_t decoded_len = full_blocks * 3U + (rem == 2U ? 1U : (rem == 3U ? 2U : 0U));

    if (output_capacity < decoded_len)
    {
        return false;
    }

    size_t out_idx = 0;
    size_t in_idx  = 0;

    for (size_t b = 0; b < full_blocks; ++b)
    {
        int c0 = base64UrlCharValue(input[in_idx++]);
        int c1 = base64UrlCharValue(input[in_idx++]);
        int c2 = base64UrlCharValue(input[in_idx++]);
        int c3 = base64UrlCharValue(input[in_idx++]);

        if (c0 < 0 || c1 < 0 || c2 < 0 || c3 < 0)
        {
            return false;
        }

        output[out_idx++] = (uint8_t) ((c0 << 2) | (c1 >> 4));
        output[out_idx++] = (uint8_t) (((c1 & 0xF) << 4) | (c2 >> 2));
        output[out_idx++] = (uint8_t) (((c2 & 0x3) << 6) | c3);
    }

    if (rem == 2U)
    {
        int c0 = base64UrlCharValue(input[in_idx++]);
        int c1 = base64UrlCharValue(input[in_idx++]);

        if (c0 < 0 || c1 < 0)
        {
            return false;
        }

        output[out_idx++] = (uint8_t) ((c0 << 2) | (c1 >> 4));
    }
    else if (rem == 3U)
    {
        int c0 = base64UrlCharValue(input[in_idx++]);
        int c1 = base64UrlCharValue(input[in_idx++]);
        int c2 = base64UrlCharValue(input[in_idx++]);

        if (c0 < 0 || c1 < 0 || c2 < 0)
        {
            return false;
        }

        output[out_idx++] = (uint8_t) ((c0 << 2) | (c1 >> 4));
        output[out_idx++] = (uint8_t) (((c1 & 0xF) << 4) | (c2 >> 2));
    }

    if (output_len != NULL)
    {
        *output_len = decoded_len;
    }

    return true;
}
