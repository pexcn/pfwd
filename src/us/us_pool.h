#ifndef PORTFWD_US_POOL_H
#define PORTFWD_US_POOL_H

#include <stdint.h>

/* Fixed-capacity object pool. The whole slab is allocated once, when the
 * worker starts; the forwarding path never calls malloc(). pool_alloc() and
 * pool_free() are O(1) freelist operations and the pool never grows: running
 * out is a normal, counted condition, not a reason to allocate.
 *
 * Every slot carries a generation counter that is bumped on free. Epoll
 * tokens embed the low 16 bits of it (see union ev_token), so an event queued
 * before the object went away resolves to NULL instead of to whatever now
 * occupies the slot. See the design manual, 4.6 and 10.2. */
struct pool {
	void     *slab;        /* single contiguous allocation           */
	void     *freelist;    /* intrusive singly-linked list           */
	uint32_t *generation;  /* parallel array, one entry per slot     */
	uint8_t  *used;        /* parallel array, for incremental sweeps */
	uint32_t  nslots;
	uint32_t  nused;
	uint32_t  obj_size;    /* rounded up for alignment               */
	uint32_t  gen_off;     /* offset of the generation field         */
	uint32_t  next_off;    /* offset of the free_next field          */
};

int   pool_init(struct pool *p, uint32_t nslots, uint32_t obj_size,
		uint32_t gen_off, uint32_t next_off);
void  pool_fini(struct pool *p);

/* Returns a zeroed object whose generation field holds the slot's current
 * generation, or NULL when the pool is exhausted. */
void *pool_alloc(struct pool *p);
void  pool_free(struct pool *p, void *obj);

/* NULL when the slot is free or the generation no longer matches. */
void *pool_resolve(const struct pool *p, uint32_t slot, uint16_t gen16);

uint32_t pool_slot_of(const struct pool *p, const void *obj);

/* Walks live objects for the incremental sweeps (TCP idle timeout, UDP
 * session aging). NULL when the slot is not in use. */
void *pool_slot_obj(const struct pool *p, uint32_t slot);

#endif /* PORTFWD_US_POOL_H */
