#include "../util/compat.h"
#include "us_pool.h"

#include <stdlib.h>
#include <string.h>

static void *slot_ptr(const struct pool *p, uint32_t slot)
{
	return (char *)p->slab + (size_t)slot * p->obj_size;
}

static void **next_ptr(const struct pool *p, void *obj)
{
	return (void **)((char *)obj + p->next_off);
}

static uint32_t *gen_ptr(const struct pool *p, void *obj)
{
	return (uint32_t *)((char *)obj + p->gen_off);
}

int pool_init(struct pool *p, uint32_t nslots, uint32_t obj_size,
	      uint32_t gen_off, uint32_t next_off)
{
	memset(p, 0, sizeof(*p));

	if (nslots == 0 || obj_size < sizeof(void *))
		return -1;

	obj_size = (obj_size + 7u) & ~7u;
	if (gen_off + sizeof(uint32_t) > obj_size ||
	    next_off + sizeof(void *) > obj_size)
		return -1;

	p->slab = calloc(nslots, obj_size);
	p->generation = calloc(nslots, sizeof(*p->generation));
	p->used = calloc(nslots, sizeof(*p->used));
	if (!p->slab || !p->generation || !p->used) {
		pool_fini(p);
		return -1;
	}

	p->nslots = nslots;
	p->obj_size = obj_size;
	p->gen_off = gen_off;
	p->next_off = next_off;

	/* Built back to front so that the first allocation lands in slot 0 and
	 * the slab is touched in ascending order. */
	for (uint32_t i = nslots; i-- > 0;) {
		void *obj = slot_ptr(p, i);

		*next_ptr(p, obj) = p->freelist;
		p->freelist = obj;
	}

	return 0;
}

void pool_fini(struct pool *p)
{
	free(p->slab);
	free(p->generation);
	free(p->used);
	memset(p, 0, sizeof(*p));
}

uint32_t pool_slot_of(const struct pool *p, const void *obj)
{
	return (uint32_t)(((const char *)obj - (const char *)p->slab) /
			  p->obj_size);
}

void *pool_alloc(struct pool *p)
{
	void *obj = p->freelist;
	uint32_t slot;

	if (!obj)
		return nullptr;

	p->freelist = *next_ptr(p, obj);
	slot = pool_slot_of(p, obj);

	memset(obj, 0, p->obj_size);
	*gen_ptr(p, obj) = p->generation[slot];
	p->used[slot] = 1;
	p->nused++;

	return obj;
}

void pool_free(struct pool *p, void *obj)
{
	uint32_t slot = pool_slot_of(p, obj);

	if (slot >= p->nslots || !p->used[slot])
		return;

	p->generation[slot]++;
	*gen_ptr(p, obj) = p->generation[slot];
	p->used[slot] = 0;
	p->nused--;

	*next_ptr(p, obj) = p->freelist;
	p->freelist = obj;
}

void *pool_resolve(const struct pool *p, uint32_t slot, uint16_t gen16)
{
	if (slot >= p->nslots || !p->used[slot])
		return nullptr;
	if ((uint16_t)p->generation[slot] != gen16)
		return nullptr;
	return slot_ptr(p, slot);
}

void *pool_slot_obj(const struct pool *p, uint32_t slot)
{
	if (slot >= p->nslots || !p->used[slot])
		return nullptr;
	return slot_ptr(p, slot);
}
