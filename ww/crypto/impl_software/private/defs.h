#pragma once

#include "wcrypto.h"

#define U8C(v) (v##U)
#define U32C(v) (v##U)

#define U8V(v) ((uint8_t)(v) & U8C(0xFF))
#define U32V(v) ((uint32_t)(v) & U32C(0xFFFFFFFF))

#define U8TO32_LITTLE(p) \
  (((uint32_t)((p)[0])      ) | \
   ((uint32_t)((p)[1]) <<  8) | \
   ((uint32_t)((p)[2]) << 16) | \
   ((uint32_t)((p)[3]) << 24))

#define U8TO64_LITTLE(p) \
  (((uint64_t)((p)[0])      ) | \
   ((uint64_t)((p)[1]) <<  8) | \
   ((uint64_t)((p)[2]) << 16) | \
   ((uint64_t)((p)[3]) << 24) | \
   ((uint64_t)((p)[4]) << 32) | \
   ((uint64_t)((p)[5]) << 40) | \
   ((uint64_t)((p)[6]) << 48) | \
   ((uint64_t)((p)[7]) << 56))

#define U16TO8_BIG(p, v) \
  do { \
    (p)[1] = U8V((v)      ); \
    (p)[0] = U8V((v) >>  8); \
  } while (0)

#define U32TO8_LITTLE(p, v) \
  do { \
    (p)[0] = U8V((v)      ); \
    (p)[1] = U8V((v) >>  8); \
    (p)[2] = U8V((v) >> 16); \
    (p)[3] = U8V((v) >> 24); \
  } while (0)

#define U32TO8_BIG(p, v) \
  do { \
    (p)[3] = U8V((v)      ); \
    (p)[2] = U8V((v) >>  8); \
    (p)[1] = U8V((v) >> 16); \
    (p)[0] = U8V((v) >> 24); \
  } while (0)

#define U64TO8_LITTLE(p, v) \
  do { \
    (p)[0] = U8V((v)      ); \
    (p)[1] = U8V((v) >>  8); \
    (p)[2] = U8V((v) >> 16); \
    (p)[3] = U8V((v) >> 24); \
    (p)[4] = U8V((v) >> 32); \
    (p)[5] = U8V((v) >> 40); \
    (p)[6] = U8V((v) >> 48); \
    (p)[7] = U8V((v) >> 56); \
} while (0)

#define U64TO8_BIG(p, v) \
  do { \
    (p)[7] = U8V((v)      ); \
    (p)[6] = U8V((v) >>  8); \
    (p)[5] = U8V((v) >> 16); \
    (p)[4] = U8V((v) >> 24); \
    (p)[3] = U8V((v) >> 32); \
    (p)[2] = U8V((v) >> 40); \
    (p)[1] = U8V((v) >> 48); \
    (p)[0] = U8V((v) >> 56); \
} while (0)



#define X25519_BYTES (256/8)

/* The base point (9) */
extern const unsigned char X25519_BASE_POINT[X25519_BYTES];

/** Number of bytes in an EC public key */
#define EC_PUBLIC_BYTES 32

/** Number of bytes in an EC private key */
#define EC_PRIVATE_BYTES 32

/**
 * Number of bytes in a Schnorr challenge.
 * Could be set to 16 in a pinch.  (FUTURE?)
 */
#define EC_CHALLENGE_BYTES 32

/** Enough bytes to get a uniform sample mod #E.  For eg a Brainpool
 * curve this would need to be more than for a private key, but due
 * to the special prime used by Curve25519, the same size is enough.
 */
#define EC_UNIFORM_BYTES 32

/* x25519 scalar multiplication.  Sets out to scalar*base.
 *
 * If clamp is set (and supported by X25519_INTEROP_SUPPORT_CLAMP)
 * then the scalar will be "clamped" like a Curve25519 secret key.
 * This adds almost no security, but permits interop with other x25519
 * implementations without manually clamping the keys.
 *
 * Per RFC 7748, this function returns failure (-1) if the output
 * is zero and clamp is set.  This indicates "non-contributory behavior",
 * meaning that one party might steer the key so that the other party's
 * contribution doesn't matter, or contributes only a little entropy.
 *
 * WARNING: however, this function differs from RFC 7748 in another way:
 * it pays attention to the high bit base[EC_PUBLIC_BYTES-1] & 0x80, but
 * RFC 7748 says to ignore this bit.  For compatibility with RFC 7748,
 * you must also clear this bit by running base[EC_PUBLIC_BYTES-1] &= 0x7F.
 * This library won't clear it for you because it takes the base point as
 * const, and (depending on build flags) dosen't copy it.
 *
 * If clamp==0, or if X25519_INTEROP_SUPPORT_CLAMP==0, then this function
 * always returns 0.
 */
// defined in wcrypto.h
// int x25519 (
//     unsigned char out[EC_PUBLIC_BYTES],
//     const unsigned char scalar[EC_PRIVATE_BYTES],
//     const unsigned char base[EC_PUBLIC_BYTES],
//     int clamp
// );

/**
 * Returns 0 on success, -1 on failure.
 *
 * Per RFC 7748, this function returns failure if the output
 * is zero and clamp is set.  This usually doesn't matter for
 * base scalarmuls.
 *
 * If clamp==0, or if X25519_INTEROP_SUPPORT_CLAMP==0, then this function
 * always returns 0.
 *
 * Same as x255(out,scalar,X255_BASE_POINT), except that
 * other implementations may optimize it.
 */
static inline int x25519_base (
    unsigned char out[EC_PUBLIC_BYTES],
    const unsigned char scalar[EC_PRIVATE_BYTES],
    int clamp
) {
	(void)clamp;

    return performX25519(out,scalar,X25519_BASE_POINT);
}

/**
 * As x25519_base, but with a scalar that's EC_UNIFORM_BYTES long,
 * and clamp always 0 (and thus, no return value).
 *
 * This is used for signing.  Implementors must replace it for
 * curves that require more bytes for uniformity (Brainpool).
 */
static inline void x25519_base_uniform (
    unsigned char out[EC_PUBLIC_BYTES],
    const unsigned char scalar[EC_UNIFORM_BYTES]
) {
    (void)x25519_base(out,scalar,0);
}

/**
 * STROBE-compatible Schnorr signatures using curve25519 (not ed25519)
 *
 * The user will call x25519_base_uniform(eph,eph_secret) to schedule
 * a random ephemeral secret key.  They then call a Schnorr oracle to
 * get a challenge, and compute the response using this function.
 */
void x25519_sign_p2 (
    unsigned char response[EC_PRIVATE_BYTES],
    const unsigned char challenge[EC_CHALLENGE_BYTES],
    const unsigned char eph_secret[EC_UNIFORM_BYTES],
    const unsigned char secret[EC_PRIVATE_BYTES]
);

/**
 * STROBE-compatible signature verification using curve25519 (not ed25519).
 * This function is the public equivalent x25519_sign_p2, taking the long-term
 * and ephemeral public keys instead of secret ones.
 *
 * Returns -1 on failure and 0 on success.
 */
int x25519_verify_p2 (
    const unsigned char response[X25519_BYTES],
    const unsigned char challenge[X25519_BYTES],
    const unsigned char eph[X25519_BYTES],
    const unsigned char pub[X25519_BYTES]
);



typedef struct poly1305_context {
	size_t aligner;
	unsigned char opaque[136];
} poly1305_context;

void poly1305_init(poly1305_context *ctx, const unsigned char key[32]);
void poly1305_update(poly1305_context *ctx, const unsigned char *m, size_t bytes);
void poly1305_finish(poly1305_context *ctx, unsigned char mac[16]);


// Taken from https://github.com/floodyberry/poly1305-donna - public domain or MIT
/*
	poly1305 implementation using 32 bit * 32 bit = 64 bit multiplication and 64 bit addition
*/

#if defined(_MSC_VER)
	#define POLY1305_NOINLINE __declspec(noinline)
#elif defined(__GNUC__)
	#define POLY1305_NOINLINE __attribute__((noinline))
#else
	#define POLY1305_NOINLINE
#endif

#define poly1305_block_size 16

/* 17 + sizeof(size_t) + 14*sizeof(unsigned long) */
typedef struct poly1305_state_internal_t {
	unsigned long r[5];
	unsigned long h[5];
	unsigned long pad[4];
	size_t leftover;
	unsigned char buffer[poly1305_block_size];
	unsigned char final;
} poly1305_state_internal_t;

/* interpret four 8 bit unsigned integers as a 32 bit unsigned integer in little endian */
static unsigned long
U8TO32(const unsigned char *p) {
	return
		(((unsigned long)(p[0] & 0xff)      ) |
	     ((unsigned long)(p[1] & 0xff) <<  8) |
         ((unsigned long)(p[2] & 0xff) << 16) |
         ((unsigned long)(p[3] & 0xff) << 24));
}

/* store a 32 bit unsigned integer as four 8 bit unsigned integers in little endian */
static void
U32TO8(unsigned char *p, unsigned long v) {
	p[0] = (v      ) & 0xff;
	p[1] = (v >>  8) & 0xff;
	p[2] = (v >> 16) & 0xff;
	p[3] = (v >> 24) & 0xff;
}

static void
poly1305_blocks(poly1305_state_internal_t *st, const unsigned char *m, size_t bytes) {
	const unsigned long hibit = (st->final) ? 0 : (1UL << 24); /* 1 << 128 */
	unsigned long r0,r1,r2,r3,r4;
	unsigned long s1,s2,s3,s4;
	unsigned long h0,h1,h2,h3,h4;
	unsigned long long d0,d1,d2,d3,d4;
	unsigned long c;

	r0 = st->r[0];
	r1 = st->r[1];
	r2 = st->r[2];
	r3 = st->r[3];
	r4 = st->r[4];

	s1 = r1 * 5;
	s2 = r2 * 5;
	s3 = r3 * 5;
	s4 = r4 * 5;

	h0 = st->h[0];
	h1 = st->h[1];
	h2 = st->h[2];
	h3 = st->h[3];
	h4 = st->h[4];

	while (bytes >= poly1305_block_size) {
		/* h += m[i] */
		h0 += (U8TO32(m+ 0)     ) & 0x3ffffff;
		h1 += (U8TO32(m+ 3) >> 2) & 0x3ffffff;
		h2 += (U8TO32(m+ 6) >> 4) & 0x3ffffff;
		h3 += (U8TO32(m+ 9) >> 6) & 0x3ffffff;
		h4 += (U8TO32(m+12) >> 8) | hibit;

		/* h *= r */
		d0 = ((unsigned long long)h0 * r0) + ((unsigned long long)h1 * s4) + ((unsigned long long)h2 * s3) + ((unsigned long long)h3 * s2) + ((unsigned long long)h4 * s1);
		d1 = ((unsigned long long)h0 * r1) + ((unsigned long long)h1 * r0) + ((unsigned long long)h2 * s4) + ((unsigned long long)h3 * s3) + ((unsigned long long)h4 * s2);
		d2 = ((unsigned long long)h0 * r2) + ((unsigned long long)h1 * r1) + ((unsigned long long)h2 * r0) + ((unsigned long long)h3 * s4) + ((unsigned long long)h4 * s3);
		d3 = ((unsigned long long)h0 * r3) + ((unsigned long long)h1 * r2) + ((unsigned long long)h2 * r1) + ((unsigned long long)h3 * r0) + ((unsigned long long)h4 * s4);
		d4 = ((unsigned long long)h0 * r4) + ((unsigned long long)h1 * r3) + ((unsigned long long)h2 * r2) + ((unsigned long long)h3 * r1) + ((unsigned long long)h4 * r0);

		/* (partial) h %= p */
		              c = (unsigned long)(d0 >> 26); h0 = (unsigned long)d0 & 0x3ffffff;
		d1 += c;      c = (unsigned long)(d1 >> 26); h1 = (unsigned long)d1 & 0x3ffffff;
		d2 += c;      c = (unsigned long)(d2 >> 26); h2 = (unsigned long)d2 & 0x3ffffff;
		d3 += c;      c = (unsigned long)(d3 >> 26); h3 = (unsigned long)d3 & 0x3ffffff;
		d4 += c;      c = (unsigned long)(d4 >> 26); h4 = (unsigned long)d4 & 0x3ffffff;
		h0 += c * 5;  c =                (h0 >> 26); h0 =                h0 & 0x3ffffff;
		h1 += c;

		m += poly1305_block_size;
		bytes -= poly1305_block_size;
	}

	st->h[0] = h0;
	st->h[1] = h1;
	st->h[2] = h2;
	st->h[3] = h3;
	st->h[4] = h4;
}


#define CHACHA20_BLOCK_SIZE		(64)
#define CHACHA20_KEY_SIZE		(32)

struct chacha20_ctx {
	uint32_t state[16];
};

void chacha20_init(struct chacha20_ctx *ctx, const uint8_t *key, const uint64_t nonce);
void chacha20(struct chacha20_ctx *ctx, uint8_t *out, const uint8_t *in, uint32_t len);
void hchacha20(uint8_t *out, const uint8_t *nonce, const uint8_t *key);




