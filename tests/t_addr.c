/* Unit test: address parsing round-trips and rejects what it must reject. */

#include "../src/util/compat.h"
#include "../src/addr.h"

#include <arpa/inet.h>
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

static void t_roundtrip(void)
{
	static const char *const inputs[] = {
		"0.0.0.0:80",
		"127.0.0.1:1",
		"255.255.255.255:65535",
		"192.168.1.7:22",
		"[::]:80",
		"[::1]:53",
		"[2001:db8::2]:80",
		"[fe80::1]:65535",
	};

	for (unsigned i = 0; i < PF_ARRAY_LEN(inputs); i++) {
		union sockaddr_inx a, b;
		char buf[ADDR_STR_MAX], buf2[ADDR_STR_MAX];

		CHECK(addr_parse(inputs[i], &a, AF_UNSPEC) == ADDR_OK,
		      "parse failed for '%s'", inputs[i]);
		CHECK(addr_format(&a, buf, sizeof(buf)) > 0,
		      "format failed for '%s'", inputs[i]);
		CHECK(strcmp(buf, inputs[i]) == 0,
		      "format mismatch: '%s' -> '%s'", inputs[i], buf);

		CHECK(addr_parse(buf, &b, AF_UNSPEC) == ADDR_OK,
		      "re-parse failed for '%s'", buf);
		CHECK(addr_format(&b, buf2, sizeof(buf2)) > 0, "re-format failed");
		CHECK(strcmp(buf, buf2) == 0, "not idempotent: '%s' vs '%s'",
		      buf, buf2);
		CHECK(addr_equal(&a, &b), "addr_equal false for '%s'", inputs[i]);
	}
}

static void t_fields(void)
{
	union sockaddr_inx a;

	CHECK(addr_parse("192.168.1.7:22", &a, AF_UNSPEC) == ADDR_OK, "parse v4");
	CHECK(is_v4(&a), "expected AF_INET");
	CHECK(ntohs(port_of_sockaddr(&a)) == 22, "expected port 22");
	CHECK(addrlen_of_sockaddr(&a) == 4, "expected 4 address octets");
	CHECK(sizeof_sockaddr(&a) == sizeof(struct sockaddr_in), "v4 socklen");
	CHECK(!addr_is_wildcard(&a), "192.168.1.7 is not a wildcard");

	CHECK(addr_parse("[2001:db8::2]:80", &a, AF_UNSPEC) == ADDR_OK, "parse v6");
	CHECK(is_v6(&a), "expected AF_INET6");
	CHECK(ntohs(port_of_sockaddr(&a)) == 80, "expected port 80");
	CHECK(addrlen_of_sockaddr(&a) == 16, "expected 16 address octets");
	CHECK(sizeof_sockaddr(&a) == sizeof(struct sockaddr_in6), "v6 socklen");

	CHECK(addr_parse("0.0.0.0:1022", &a, AF_UNSPEC) == ADDR_OK, "parse any4");
	CHECK(addr_is_wildcard(&a), "0.0.0.0 is a wildcard");
	CHECK(addr_is_local(&a) == 1, "wildcard counts as local");

	CHECK(addr_parse("[::]:1701", &a, AF_UNSPEC) == ADDR_OK, "parse any6");
	CHECK(addr_is_wildcard(&a), "[::] is a wildcard");

	CHECK(addr_parse("127.0.0.1:53", &a, AF_UNSPEC) == ADDR_OK, "parse lo4");
	CHECK(addr_is_local(&a) == 1, "127.0.0.1 is local");

	CHECK(addr_parse(":8080", &a, AF_INET6) == ADDR_OK, "empty host");
	CHECK(is_v6(&a) && addr_is_wildcard(&a), "empty host -> wildcard v6");
}

static void t_reject(void)
{
	static const char *const bad[] = {
		"",
		"1.2.3.4",             /* no port                       */
		"1.2.3.4:",            /* empty port                    */
		"1.2.3.4:70000",       /* port out of range             */
		"1.2.3.4:http",        /* service names are not allowed */
		"::1:53",              /* bare IPv6 literal             */
		"[2001:db8::2]80",     /* missing colon                 */
		"[2001:db8::2:80",     /* unterminated bracket          */
		"[]:80",               /* empty bracketed host          */
		"1.2.3.4:-1",
	};

	for (unsigned i = 0; i < PF_ARRAY_LEN(bad); i++) {
		union sockaddr_inx a;

		CHECK(addr_parse(bad[i], &a, AF_UNSPEC) != ADDR_OK,
		      "'%s' should have been rejected", bad[i]);
	}
}

static void t_equal_and_hash(void)
{
	union sockaddr_inx a, b, c;

	CHECK(addr_parse("10.0.0.1:1000", &a, AF_UNSPEC) == ADDR_OK, "parse a");
	CHECK(addr_parse("10.0.0.1:1000", &b, AF_UNSPEC) == ADDR_OK, "parse b");
	CHECK(addr_parse("10.0.0.1:1001", &c, AF_UNSPEC) == ADDR_OK, "parse c");

	CHECK(addr_equal(&a, &b), "same address must compare equal");
	CHECK(!addr_equal(&a, &c), "different ports must not compare equal");
	CHECK(addr_hash(&a, 1234) == addr_hash(&b, 1234), "hash must be stable");
	CHECK(addr_hash(&a, 1234) != addr_hash(&a, 5678),
	      "hash must depend on the seed");

	/* An IPv4 and an IPv6 address are never equal, even when they look
	 * alike after mapping. */
	CHECK(addr_parse("[::ffff:10.0.0.1]:1000", &c, AF_UNSPEC) == ADDR_OK,
	      "parse v4-mapped");
	CHECK(!addr_equal(&a, &c), "cross-family compare must be false");
}

static void t_truncation(void)
{
	union sockaddr_inx a;
	char small[8];

	CHECK(addr_parse("[2001:db8::2]:80", &a, AF_UNSPEC) == ADDR_OK, "parse");
	CHECK(addr_format(&a, small, sizeof(small)) < 0,
	      "format must fail rather than truncate");
}

int main(void)
{
	t_roundtrip();
	t_fields();
	t_reject();
	t_equal_and_hash();
	t_truncation();

	if (failures) {
		printf("t_addr: %u failure(s)\n", failures);
		return 1;
	}
	printf("t_addr: all checks passed\n");
	return 0;
}
