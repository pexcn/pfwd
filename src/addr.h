#ifndef PORTFWD_ADDR_H
#define PORTFWD_ADDR_H

#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>
#include <sys/socket.h>

/* The single place where address-family differences are allowed to live.
 * Every call site passes &sa->sa plus sizeof_sockaddr(sa) and stays
 * family-agnostic. */
union sockaddr_inx {
	struct sockaddr     sa;
	struct sockaddr_in  in;
	struct sockaddr_in6 in6;
};

#define sa_family_of(p)     ((p)->sa.sa_family)
#define is_v4(p)            (sa_family_of(p) == AF_INET)
#define is_v6(p)            (sa_family_of(p) == AF_INET6)

/* Returns the port in network byte order. */
#define port_of_sockaddr(p) \
	(is_v6(p) ? (p)->in6.sin6_port : (p)->in.sin_port)

/* Returns a pointer to the raw address bytes (4 or 16 octets). */
#define addr_of_sockaddr(p) \
	((void *)(is_v6(p) ? (void *)&(p)->in6.sin6_addr : (void *)&(p)->in.sin_addr))

#define addrlen_of_sockaddr(p) \
	(is_v6(p) ? 16u : 4u)

#define sizeof_sockaddr(p) \
	(is_v6(p) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in))

/* Long enough for "[" + INET6_ADDRSTRLEN + "%" + IFNAMSIZ + "]:65535". */
#define ADDR_STR_MAX 80

enum {
	ADDR_OK          =  0,
	ADDR_ERR_SYNTAX  = -1,  /* not host:port / bad port                */
	ADDR_ERR_RESOLVE = -2,  /* getaddrinfo() failed on a host name     */
	ADDR_ERR_FAMILY  = -3,  /* resolved family excluded by the caller  */
};

/* "0.0.0.0:1022", "[::]:1701", "[2001:db8::2]:80", "example.com:80",
 * ":8080" (wildcard of default_family). default_family may be AF_UNSPEC. */
int addr_parse(const char *s, union sockaddr_inx *out, int default_family);

/* Same, but fills errbuf with an English explanation on failure. */
int addr_parse_ex(const char *s, union sockaddr_inx *out, int default_family,
		  char *errbuf, size_t errlen);

/* Always bracket-quotes IPv6, so output can be fed back into addr_parse(). */
int addr_format(const union sockaddr_inx *sa, char *buf, size_t len);

int addr_equal(const union sockaddr_inx *a, const union sockaddr_inx *b);
uint32_t addr_hash(const union sockaddr_inx *sa, uint32_t seed);
int addr_is_wildcard(const union sockaddr_inx *sa);
int addr_is_local(const union sockaddr_inx *sa);  /* for flowtable warning */

#endif /* PORTFWD_ADDR_H */
