#include "util/compat.h"
#include "addr.h"
#include "util/hash.h"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int split_host_port(const char *s, char *host, size_t hostlen,
			   char *port, size_t portlen)
{
	const char *colon;
	size_t n;

	if (*s == '[') {
		const char *end = strchr(s, ']');

		if (!end)
			return -1;
		n = (size_t)(end - s) - 1;
		if (n == 0 || n >= hostlen)
			return -1;
		memcpy(host, s + 1, n);
		host[n] = '\0';
		if (end[1] != ':')
			return -1;
		colon = end + 1;
	} else {
		colon = strrchr(s, ':');
		if (!colon)
			return -1;
		/* A second colon to the left means a bare IPv6 literal, which
		 * is ambiguous with the port separator: require brackets. */
		if (memchr(s, ':', (size_t)(colon - s)) != nullptr)
			return -1;
		n = (size_t)(colon - s);
		if (n >= hostlen)
			return -1;
		memcpy(host, s, n);
		host[n] = '\0';
	}

	if (strlen(colon + 1) >= portlen)
		return -1;
	strcpy(port, colon + 1);
	return 0;
}

static int port_is_numeric(const char *p)
{
	unsigned long v;
	char *end;

	if (!p[0])
		return 0;
	for (const char *q = p; *q; q++)
		if (*q < '0' || *q > '9')
			return 0;
	v = strtoul(p, &end, 10);
	return *end == '\0' && v <= 65535;
}

static void set_wildcard(union sockaddr_inx *out, int family, uint16_t port)
{
	memset(out, 0, sizeof(*out));
	if (family == AF_INET6) {
		out->in6.sin6_family = AF_INET6;
		out->in6.sin6_addr = in6addr_any;
		out->in6.sin6_port = htons(port);
	} else {
		out->in.sin_family = AF_INET;
		out->in.sin_addr.s_addr = htonl(INADDR_ANY);
		out->in.sin_port = htons(port);
	}
}

int addr_parse_ex(const char *s, union sockaddr_inx *out, int default_family,
		  char *errbuf, size_t errlen)
{
	char host[256], port[16];
	struct addrinfo hints = {}, *res = nullptr;
	int rc;

	if (errbuf && errlen)
		errbuf[0] = '\0';

	if (!s || !*s) {
		if (errbuf)
			snprintf(errbuf, errlen, "empty address");
		return ADDR_ERR_SYNTAX;
	}
	if (split_host_port(s, host, sizeof(host), port, sizeof(port)) < 0) {
		if (errbuf)
			snprintf(errbuf, errlen,
				 "expected HOST:PORT (IPv6 literals must be bracketed)");
		return ADDR_ERR_SYNTAX;
	}
	if (!port_is_numeric(port)) {
		if (errbuf)
			snprintf(errbuf, errlen,
				 "port '%s' is not a number in 0..65535", port);
		return ADDR_ERR_SYNTAX;
	}

	if (host[0] == '\0') {
		set_wildcard(out, default_family == AF_INET6 ? AF_INET6 : AF_INET,
			     (uint16_t)atoi(port));
		return ADDR_OK;
	}

	hints.ai_family = default_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

	rc = getaddrinfo(host, port, &hints, &res);
	if (rc != 0) {
		/* Not a literal: fall back to name resolution. */
		hints.ai_flags = AI_NUMERICSERV | AI_ADDRCONFIG;
		rc = getaddrinfo(host, port, &hints, &res);
		if (rc != 0) {
			if (errbuf)
				snprintf(errbuf, errlen, "%s", gai_strerror(rc));
			return ADDR_ERR_RESOLVE;
		}
	}

	if (res->ai_addrlen > sizeof(*out) ||
	    (res->ai_family != AF_INET && res->ai_family != AF_INET6)) {
		freeaddrinfo(res);
		if (errbuf)
			snprintf(errbuf, errlen, "unsupported address family");
		return ADDR_ERR_FAMILY;
	}

	memset(out, 0, sizeof(*out));
	memcpy(out, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	return ADDR_OK;
}

int addr_parse(const char *s, union sockaddr_inx *out, int default_family)
{
	return addr_parse_ex(s, out, default_family, nullptr, 0);
}

int addr_format(const union sockaddr_inx *sa, char *buf, size_t len)
{
	char ip[INET6_ADDRSTRLEN];
	int n;

	if (!inet_ntop(sa_family_of(sa), addr_of_sockaddr(sa), ip, sizeof(ip)))
		return -1;

	if (is_v6(sa))
		n = snprintf(buf, len, "[%s]:%u", ip,
			     (unsigned)ntohs(port_of_sockaddr(sa)));
	else
		n = snprintf(buf, len, "%s:%u", ip,
			     (unsigned)ntohs(port_of_sockaddr(sa)));

	if (n < 0 || (size_t)n >= len)
		return -1;
	return n;
}

int addr_equal(const union sockaddr_inx *a, const union sockaddr_inx *b)
{
	if (sa_family_of(a) != sa_family_of(b))
		return 0;
	if (port_of_sockaddr(a) != port_of_sockaddr(b))
		return 0;
	if (is_v6(a) && a->in6.sin6_scope_id != b->in6.sin6_scope_id)
		return 0;
	return memcmp(addr_of_sockaddr(a), addr_of_sockaddr(b),
		      addrlen_of_sockaddr(a)) == 0;
}

uint32_t addr_hash(const union sockaddr_inx *sa, uint32_t seed)
{
	uint8_t buf[19];
	unsigned alen = addrlen_of_sockaddr(sa);

	buf[0] = (uint8_t)(is_v6(sa) ? 6 : 4);
	memcpy(buf + 1, addr_of_sockaddr(sa), alen);
	memcpy(buf + 1 + alen, &(uint16_t){ port_of_sockaddr(sa) }, 2);
	return hash32(buf, 1u + alen + 2u, seed);
}

int addr_is_wildcard(const union sockaddr_inx *sa)
{
	static const struct in6_addr any6;

	if (is_v6(sa))
		return memcmp(&sa->in6.sin6_addr, &any6, 16) == 0;
	return sa->in.sin_addr.s_addr == htonl(INADDR_ANY);
}

int addr_is_local(const union sockaddr_inx *sa)
{
	struct ifaddrs *ifs = nullptr;
	int found = 0;

	if (addr_is_wildcard(sa))
		return 1;
	if (is_v4(sa) && (ntohl(sa->in.sin_addr.s_addr) >> 24) == 127u)
		return 1;
	if (is_v6(sa) && IN6_IS_ADDR_LOOPBACK(&sa->in6.sin6_addr))
		return 1;

	if (getifaddrs(&ifs) != 0)
		return -1;

	for (struct ifaddrs *p = ifs; p && !found; p = p->ifa_next) {
		if (!p->ifa_addr || p->ifa_addr->sa_family != sa_family_of(sa))
			continue;
		if (is_v6(sa)) {
			const struct sockaddr_in6 *s6 =
				(const struct sockaddr_in6 *)p->ifa_addr;

			found = memcmp(&s6->sin6_addr, &sa->in6.sin6_addr, 16) == 0;
		} else {
			const struct sockaddr_in *s4 =
				(const struct sockaddr_in *)p->ifa_addr;

			found = s4->sin_addr.s_addr == sa->in.sin_addr.s_addr;
		}
	}

	freeifaddrs(ifs);
	return found;
}
