#ifndef PORTFWD_UTIL_HASH_H
#define PORTFWD_UTIL_HASH_H

#include <stddef.h>
#include <stdint.h>

/* SipHash-1-2: keyed, fast, and resistant to the hash-flooding attacks a
 * publicly reachable session table is exposed to. */
uint64_t siphash_1_2(const void *data, size_t len, const uint8_t key[16]);

/* Derives a 128-bit SipHash key from a 32-bit per-worker seed. */
void hash_key_from_seed(uint32_t seed, uint8_t key[16]);

/* Convenience wrapper returning the folded low 32 bits. */
uint32_t hash32(const void *data, size_t len, uint32_t seed);

#endif /* PORTFWD_UTIL_HASH_H */
