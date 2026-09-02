#include "compat.h"
#include "hash.h"

#include <string.h>

#define ROTL64(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))

#define SIPROUND                                                              \
	do {                                                                  \
		v0 += v1;                                                     \
		v1 = ROTL64(v1, 13);                                          \
		v1 ^= v0;                                                     \
		v0 = ROTL64(v0, 32);                                          \
		v2 += v3;                                                     \
		v3 = ROTL64(v3, 16);                                          \
		v3 ^= v2;                                                     \
		v0 += v3;                                                     \
		v3 = ROTL64(v3, 21);                                          \
		v3 ^= v0;                                                     \
		v2 += v1;                                                     \
		v1 = ROTL64(v1, 17);                                          \
		v1 ^= v2;                                                     \
		v2 = ROTL64(v2, 32);                                          \
	} while (0)

static inline uint64_t load64le(const uint8_t *p)
{
	return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) |
	       ((uint64_t)p[3] << 24) | ((uint64_t)p[4] << 32) |
	       ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48) |
	       ((uint64_t)p[7] << 56);
}

uint64_t siphash_1_2(const void *data, size_t len, const uint8_t key[16])
{
	const uint8_t *in = data;
	uint64_t k0 = load64le(key);
	uint64_t k1 = load64le(key + 8);
	uint64_t v0 = UINT64_C(0x736f6d6570736575) ^ k0;
	uint64_t v1 = UINT64_C(0x646f72616e646f6d) ^ k1;
	uint64_t v2 = UINT64_C(0x6c7967656e657261) ^ k0;
	uint64_t v3 = UINT64_C(0x7465646279746573) ^ k1;
	uint64_t b = (uint64_t)len << 56;
	const uint8_t *end = in + (len - (len % 8));

	for (; in != end; in += 8) {
		uint64_t m = load64le(in);
		v3 ^= m;
		SIPROUND;
		v0 ^= m;
	}

	switch (len & 7) {
	case 7:
		b |= (uint64_t)in[6] << 48;
		[[fallthrough]];
	case 6:
		b |= (uint64_t)in[5] << 40;
		[[fallthrough]];
	case 5:
		b |= (uint64_t)in[4] << 32;
		[[fallthrough]];
	case 4:
		b |= (uint64_t)in[3] << 24;
		[[fallthrough]];
	case 3:
		b |= (uint64_t)in[2] << 16;
		[[fallthrough]];
	case 2:
		b |= (uint64_t)in[1] << 8;
		[[fallthrough]];
	case 1:
		b |= (uint64_t)in[0];
		break;
	default:
		break;
	}

	v3 ^= b;
	SIPROUND;
	v0 ^= b;

	v2 ^= 0xff;
	SIPROUND;
	SIPROUND;

	return v0 ^ v1 ^ v2 ^ v3;
}

void hash_key_from_seed(uint32_t seed, uint8_t key[16])
{
	uint64_t a = UINT64_C(0x9e3779b97f4a7c15) * (uint64_t)(seed + 1u);
	uint64_t b = UINT64_C(0xbf58476d1ce4e5b9) ^ ((uint64_t)seed << 32 | seed);

	for (unsigned i = 0; i < 8; i++) {
		key[i] = (uint8_t)(a >> (i * 8));
		key[8 + i] = (uint8_t)(b >> (i * 8));
	}
}

uint32_t hash32(const void *data, size_t len, uint32_t seed)
{
	uint8_t key[16];
	uint64_t h;

	hash_key_from_seed(seed, key);
	h = siphash_1_2(data, len, key);
	return (uint32_t)(h ^ (h >> 32));
}
