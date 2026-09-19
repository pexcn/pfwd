/* Unit test: object pool allocation, release, generation invalidation and
 * exhaustion behaviour. */

#include "../src/util/compat.h"
#include "../src/us/us_pool.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

static unsigned failures;

#define CHECK(cond, ...)                                                      \
	do {                                                                  \
		if (!(cond)) {                                                \
			printf("FAIL %s:%d: ", __FILE__, __LINE__);           \
			printf(__VA_ARGS__);                                  \
			printf("\n");                                         \
			failures++;                                           \
		}                                                             \
	} while (0)

struct tobj {
	uint64_t     payload;
	uint32_t     generation;
	uint32_t     slot;
	struct tobj *free_next;
};

#define NSLOTS 64u

static int pool_open(struct pool *p, uint32_t nslots)
{
	return pool_init(p, nslots, sizeof(struct tobj),
			 offsetof(struct tobj, generation),
			 offsetof(struct tobj, free_next));
}

static void t_alloc_exhaust(void)
{
	struct tobj *objs[NSLOTS];
	struct pool p;

	CHECK(pool_open(&p, NSLOTS) == 0, "pool_init failed");

	for (unsigned i = 0; i < NSLOTS; i++) {
		objs[i] = pool_alloc(&p);
		CHECK(objs[i] != nullptr, "allocation %u failed", i);
		objs[i]->slot = pool_slot_of(&p, objs[i]);
		objs[i]->payload = 0x1000u + i;
	}
	CHECK(p.nused == NSLOTS, "nused=%u, want %u", p.nused, NSLOTS);
	CHECK(pool_alloc(&p) == nullptr, "an exhausted pool must return NULL");

	/* Distinct slots, and the payloads survived the round. */
	for (unsigned i = 0; i < NSLOTS; i++) {
		CHECK(objs[i]->slot == i, "slot %u, want %u", objs[i]->slot, i);
		CHECK(objs[i]->payload == 0x1000u + i, "payload clobbered at %u", i);
	}

	for (unsigned i = 0; i < NSLOTS; i++)
		pool_free(&p, objs[i]);
	CHECK(p.nused == 0, "nused=%u after freeing everything", p.nused);
	CHECK(pool_alloc(&p) != nullptr, "the pool must be reusable after free");

	pool_fini(&p);
}

static void t_alloc_zeroes(void)
{
	struct tobj *a, *b;
	struct pool p;

	CHECK(pool_open(&p, 1) == 0, "pool_init failed");

	a = pool_alloc(&p);
	CHECK(a != nullptr, "allocation failed");
	a->payload = 0xdeadbeefu;
	pool_free(&p, a);

	b = pool_alloc(&p);
	CHECK(b == a, "the only slot must come back");
	CHECK(b->payload == 0, "pool_alloc must hand out a zeroed object");
	CHECK(b->generation == p.generation[0],
	      "the object must carry its slot's generation");

	pool_fini(&p);
}

static void t_generation(void)
{
	struct tobj *a, *b;
	uint32_t slot;
	uint16_t stale;
	struct pool p;

	CHECK(pool_open(&p, NSLOTS) == 0, "pool_init failed");

	a = pool_alloc(&p);
	CHECK(a != nullptr, "allocation failed");
	slot = pool_slot_of(&p, a);
	stale = (uint16_t)a->generation;

	CHECK(pool_resolve(&p, slot, stale) == a, "a live token must resolve");
	CHECK(pool_resolve(&p, slot, (uint16_t)(stale + 1)) == nullptr,
	      "a mismatched generation must not resolve");
	CHECK(pool_resolve(&p, NSLOTS, stale) == nullptr,
	      "an out-of-range slot must not resolve");

	pool_free(&p, a);
	CHECK(pool_resolve(&p, slot, stale) == nullptr,
	      "a token for a freed slot must not resolve");

	/* The slot comes straight back, but under a new generation: an event
	 * queued for the old occupant must not land on the new one. */
	b = pool_alloc(&p);
	CHECK(b == a, "the freed slot should be reused first");
	CHECK(pool_resolve(&p, slot, stale) == nullptr,
	      "a stale token must not resolve onto a recycled slot");
	CHECK(pool_resolve(&p, slot, (uint16_t)b->generation) == b,
	      "the new token must resolve");

	pool_fini(&p);
}

static void t_generation_monotonic(void)
{
	struct pool p;

	CHECK(pool_open(&p, 1) == 0, "pool_init failed");

	for (unsigned i = 0; i < 1000; i++) {
		struct tobj *o = pool_alloc(&p);

		CHECK(o != nullptr, "allocation %u failed", i);
		CHECK(o->generation == i, "generation %u, want %u",
		      o->generation, i);
		CHECK(pool_resolve(&p, 0, (uint16_t)o->generation) == o,
		      "resolve failed at round %u", i);
		pool_free(&p, o);
	}
	CHECK(p.generation[0] == 1000, "generation=%u after 1000 rounds",
	      p.generation[0]);

	pool_fini(&p);
}

static void t_slot_walk(void)
{
	struct tobj *objs[8];
	unsigned live = 0;
	struct pool p;

	CHECK(pool_open(&p, 8) == 0, "pool_init failed");

	for (unsigned i = 0; i < 8; i++)
		objs[i] = pool_alloc(&p);
	for (unsigned i = 0; i < 8; i += 2)
		pool_free(&p, objs[i]);

	for (uint32_t i = 0; i < p.nslots; i++) {
		void *o = pool_slot_obj(&p, i);

		if (o) {
			live++;
			CHECK((i & 1u) == 1u, "slot %u should be free", i);
		}
	}
	CHECK(live == 4, "walk found %u live objects, want 4", live);
	CHECK(pool_slot_obj(&p, p.nslots) == nullptr,
	      "an out-of-range slot must not resolve");

	pool_fini(&p);
}

static void t_bad_init(void)
{
	struct pool p;

	CHECK(pool_init(&p, 0, sizeof(struct tobj), 0, 8) != 0,
	      "a zero-slot pool must be rejected");
	CHECK(pool_init(&p, 8, 4, 0, 0) != 0,
	      "an object smaller than a pointer must be rejected");
	CHECK(pool_init(&p, 8, sizeof(struct tobj), 1024, 0) != 0,
	      "an out-of-object generation offset must be rejected");
}

int main(void)
{
	t_alloc_exhaust();
	t_alloc_zeroes();
	t_generation();
	t_generation_monotonic();
	t_slot_walk();
	t_bad_init();

	if (failures) {
		printf("t_pool: %u failure(s)\n", failures);
		return 1;
	}
	printf("t_pool: OK\n");
	return 0;
}
