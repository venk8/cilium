// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/unspec.h>
#include "common.h"
#include "pktgen.h"

#define TEST_BPF_SOCK 1

#define ENABLE_IPV4 1
#define ENABLE_IPV6 1

#define NETNS_COOKIE 5000
#define HOST_NETNS_COOKIE 42

#define get_netns_cookie(ctx) test_get_netns_cookie(ctx)
static __always_inline
int test_get_netns_cookie(__maybe_unused const struct bpf_sock_addr *addr)
{
	return addr ? NETNS_COOKIE : HOST_NETNS_COOKIE;
}

/* A stateful stand-in for socket storage. Each test drives a single socket
 * per family, so one entry per storage map is enough to model creation,
 * reads, overwrites and deletion.
 */
static __always_inline void *
mock_sk_storage_get(const void *map, struct bpf_sock *sk, void *value,
		    __u64 flags);
static __always_inline int
mock_sk_storage_delete(const void *map, struct bpf_sock *sk);

#undef sk_storage_get
#define sk_storage_get mock_sk_storage_get
#undef sk_storage_delete
#define sk_storage_delete mock_sk_storage_delete

#include "bpf_sock.c"

#include "lib/ipcache.h"
#include "lib/lb.h"

static struct ipv4_sk_storage_entry st4;
static struct ipv6_sk_storage_entry st6;
static bool st4_valid;
static bool st6_valid;

static __always_inline void *
mock_sk_storage_get(const void *map, struct bpf_sock *sk, void *value,
		    __u64 flags)
{
	if (!sk)
		return NULL;

	if (map == &cilium_lb4_reverse_sk_v2) {
		if (!st4_valid && (flags & BPF_SK_STORAGE_GET_F_CREATE)) {
			memset(&st4, 0, sizeof(st4));
			if (value)
				memcpy(&st4, value, sizeof(st4));
			st4_valid = true;
		}
		return st4_valid ? &st4 : NULL;
	}
	if (map == &cilium_lb6_reverse_sk_v2) {
		if (!st6_valid && (flags & BPF_SK_STORAGE_GET_F_CREATE)) {
			memset(&st6, 0, sizeof(st6));
			if (value)
				memcpy(&st6, value, sizeof(st6));
			st6_valid = true;
		}
		return st6_valid ? &st6 : NULL;
	}
	return NULL;
}

static __always_inline int
mock_sk_storage_delete(const void *map, struct bpf_sock *sk __maybe_unused)
{
	if (map == &cilium_lb4_reverse_sk_v2 && st4_valid) {
		st4_valid = false;
		return 0;
	}
	if (map == &cilium_lb6_reverse_sk_v2 && st6_valid) {
		st6_valid = false;
		return 0;
	}
	return -ENOENT;
}

#define REVNAT_A	1
#define REVNAT_B	2
#define REVNAT_OTHER	9

#define SVC_PORT_A	bpf_htons(5001)
#define SVC_PORT_B	bpf_htons(5002)
#define BACKEND_PORT	bpf_htons(7000)

/* The peer argument of __sock{4,6}_xlate_rev(). */
#define RECVMSG		false
#define GETPEERNAME	true

/* Translates a reply from the backend for recvmsg() or getpeername(). */
static __always_inline int rev4(struct bpf_sock_addr *addr, bool peer)
{
	addr->user_ip4 = v4_pod_one;
	addr->user_port = BACKEND_PORT;
	return __sock4_xlate_rev(addr, addr, peer);
}

static __always_inline int rev6(struct bpf_sock_addr *addr,
				const union v6addr *backend, bool peer)
{
	memcpy(addr->user_ip6, backend, 16);
	addr->user_port = BACKEND_PORT;
	return __sock6_xlate_rev(addr, peer);
}

/* Services A and B front the same backend. A socket that talks to both can
 * only tell them apart by what it did: connect() is recorded in the socket
 * storage and the legacy map, sendto() only in the legacy map.
 */
CHECK("xdp", "sock4_revnat_storage")
int test_sock4_revnat_storage(__maybe_unused struct xdp_md *ctx)
{
	struct bpf_sock sk = {};
	struct bpf_sock_addr addr = {
		.protocol = IPPROTO_UDP,
		.sk = &sk,
	};
	/* TEST_BPF_SOCK gives every UDP socket cookie 0. */
	struct ipv4_revnat_tuple lru_key = {
		.cookie = 0,
		.address = v4_pod_one,
		.port = BACKEND_PORT,
	};
	struct ipv4_revnat_entry *lru;
	int ret;

	lb_v4_add_service(v4_svc_one, SVC_PORT_A, IPPROTO_UDP, 1, REVNAT_A);
	lb_v4_add_backend(v4_svc_one, SVC_PORT_A, 1, 124, v4_pod_one,
			  BACKEND_PORT, IPPROTO_UDP, 0);
	lb_v4_add_service(v4_svc_two, SVC_PORT_B, IPPROTO_UDP, 1, REVNAT_B);
	lb_v4_add_backend(v4_svc_two, SVC_PORT_B, 1, 124, v4_pod_one,
			  BACKEND_PORT, IPPROTO_UDP, 0);
	/* Needed to avoid sock4_skip_xlate */
	ipcache_v4_add_entry(v4_pod_one, 0, 112233, 0, 0);
	map_delete_elem(&cilium_lb4_reverse_sk, &lru_key);
	st4_valid = false;

	test_init();

	/* connect() to A records A in the socket storage and the legacy map. */
	addr.user_ip4 = v4_svc_one;
	addr.user_port = SVC_PORT_A;
	ret = __sock4_xlate_fwd(&addr, &addr, false, true);
	assert(ret == 0);
	assert(addr.user_ip4 == v4_pod_one);
	assert(addr.user_port == BACKEND_PORT);
	assert(st4_valid);
	assert(st4.address == v4_svc_one);
	assert(st4.port == SVC_PORT_A);
	assert(st4.rev_nat_index == REVNAT_A);
	assert(st4.backend_address == v4_pod_one);
	assert(st4.backend_port == BACKEND_PORT);
	assert(map_lookup_elem(&cilium_lb4_reverse_sk, &lru_key));
	sk.dst_ip4 = v4_pod_one;
	sk.dst_port = BACKEND_PORT;

	/* While connected, both report A, also once the legacy entry has been
	 * evicted.
	 */
	ret = rev4(&addr, RECVMSG);
	assert(ret == 0);
	assert(addr.user_ip4 == v4_svc_one);
	assert(addr.user_port == SVC_PORT_A);
	map_delete_elem(&cilium_lb4_reverse_sk, &lru_key);
	ret = rev4(&addr, RECVMSG);
	assert(ret == 0);
	assert(addr.user_ip4 == v4_svc_one);
	assert(addr.user_port == SVC_PORT_A);
	ret = rev4(&addr, GETPEERNAME);
	assert(ret == 0);
	assert(addr.user_ip4 == v4_svc_one);
	assert(addr.user_port == SVC_PORT_A);

	/* sendto() B on the still connected socket leaves the storage alone and
	 * points the legacy entry at B. The reply comes from B, while the socket
	 * remains connected through A.
	 */
	addr.user_ip4 = v4_svc_two;
	addr.user_port = SVC_PORT_B;
	ret = __sock4_xlate_fwd(&addr, &addr, true, false);
	assert(ret == 0);
	assert(st4_valid);
	assert(st4.address == v4_svc_one);
	ret = rev4(&addr, RECVMSG);
	assert(ret == 0);
	assert(addr.user_ip4 == v4_svc_two);
	assert(addr.user_port == SVC_PORT_B);
	ret = rev4(&addr, GETPEERNAME);
	assert(ret == 0);
	assert(addr.user_ip4 == v4_svc_one);
	assert(addr.user_port == SVC_PORT_A);

	/* connect(AF_UNSPEC) clears the peer but runs none of our hooks, so the
	 * storage still names A. The reply to sendto() B comes from B.
	 */
	sk.dst_ip4 = 0;
	sk.dst_port = 0;
	addr.user_ip4 = v4_svc_two;
	addr.user_port = SVC_PORT_B;
	ret = __sock4_xlate_fwd(&addr, &addr, true, false);
	assert(ret == 0);
	assert(st4_valid);
	assert(st4.address == v4_svc_one);
	ret = rev4(&addr, RECVMSG);
	assert(ret == 0);
	assert(addr.user_ip4 == v4_svc_two);
	assert(addr.user_port == SVC_PORT_B);

	/* Once its legacy entry is evicted, a disconnected socket's reply is
	 * left untranslated rather than reported as coming from A.
	 */
	map_delete_elem(&cilium_lb4_reverse_sk, &lru_key);
	ret = rev4(&addr, RECVMSG);
	assert(ret == -ENXIO);
	assert(addr.user_ip4 == v4_pod_one);
	assert(addr.user_port == BACKEND_PORT);
	addr.user_ip4 = v4_svc_two;
	addr.user_port = SVC_PORT_B;
	ret = __sock4_xlate_fwd(&addr, &addr, true, false);
	assert(ret == 0);

	/* Removing A must not cost the disconnected socket its entry for B. */
	lb_v4_add_service(v4_svc_one, SVC_PORT_A, IPPROTO_UDP, 1, REVNAT_OTHER);
	ret = rev4(&addr, RECVMSG);
	assert(ret == 0);
	assert(addr.user_ip4 == v4_svc_two);
	assert(addr.user_port == SVC_PORT_B);
	assert(map_lookup_elem(&cilium_lb4_reverse_sk, &lru_key));

	/* A connected socket whose storage names the removed A drops only the
	 * storage: getpeername() falls back to the live legacy entry for B.
	 */
	sk.dst_ip4 = v4_pod_one;
	sk.dst_port = BACKEND_PORT;
	ret = rev4(&addr, GETPEERNAME);
	assert(ret == 0);
	assert(addr.user_ip4 == v4_svc_two);
	assert(addr.user_port == SVC_PORT_B);
	assert(!st4_valid);
	lru = map_lookup_elem(&cilium_lb4_reverse_sk, &lru_key);
	assert(lru);
	assert(lru->rev_nat_index == REVNAT_B);

	/* A stale legacy entry, with no storage to fall back on, is dropped and
	 * the reply is left untranslated.
	 */
	lb_v4_add_service(v4_svc_two, SVC_PORT_B, IPPROTO_UDP, 1, REVNAT_OTHER);
	ret = rev4(&addr, RECVMSG);
	assert(ret == -ENXIO);
	assert(addr.user_ip4 == v4_pod_one);
	assert(addr.user_port == BACKEND_PORT);
	assert(!map_lookup_elem(&cilium_lb4_reverse_sk, &lru_key));

	/* Storage for another backend is ignored in favour of the legacy map. */
	lb_v4_add_service(v4_svc_one, SVC_PORT_A, IPPROTO_UDP, 1, REVNAT_A);
	lb_v4_add_service(v4_svc_two, SVC_PORT_B, IPPROTO_UDP, 1, REVNAT_B);
	addr.user_ip4 = v4_svc_two;
	addr.user_port = SVC_PORT_B;
	ret = __sock4_xlate_fwd(&addr, &addr, true, false);
	assert(ret == 0);
	st4_valid = true;
	st4.address = v4_svc_one;
	st4.port = SVC_PORT_A;
	st4.rev_nat_index = REVNAT_A;
	st4.backend_address = v4_pod_two;
	st4.backend_port = BACKEND_PORT;
	ret = rev4(&addr, GETPEERNAME);
	assert(ret == 0);
	assert(addr.user_ip4 == v4_svc_two);
	assert(addr.user_port == SVC_PORT_B);
	assert(st4_valid);

	test_finish();
}

/* See test_sock4_revnat_storage. */
CHECK("xdp", "sock6_revnat_storage")
int test_sock6_revnat_storage(__maybe_unused struct xdp_md *ctx)
{
	union v6addr svc_a = {}, svc_b = {}, backend = {}, other = {};
	struct bpf_sock sk = {};
	struct bpf_sock_addr addr = {
		.protocol = IPPROTO_UDP,
		.sk = &sk,
	};
	struct ipv6_revnat_tuple lru_key = {
		.cookie = 0,
		.port = BACKEND_PORT,
	};
	struct ipv6_revnat_entry *lru;
	int ret;

	memcpy(svc_a.addr, (void *)v6_node_one, 16);
	memcpy(svc_b.addr, (void *)v6_node_two, 16);
	memcpy(backend.addr, (void *)v6_pod_one, 16);
	memcpy(other.addr, (void *)v6_pod_two, 16);
	memcpy(&lru_key.address, &backend, sizeof(backend));

	lb_v6_add_service(&svc_a, SVC_PORT_A, IPPROTO_UDP, 1, REVNAT_A);
	lb_v6_add_backend(&svc_a, SVC_PORT_A, 1, 124, &backend, BACKEND_PORT,
			  IPPROTO_UDP, 0);
	lb_v6_add_service(&svc_b, SVC_PORT_B, IPPROTO_UDP, 1, REVNAT_B);
	lb_v6_add_backend(&svc_b, SVC_PORT_B, 1, 124, &backend, BACKEND_PORT,
			  IPPROTO_UDP, 0);
	/* Needed to avoid sock6_skip_xlate */
	ipcache_v6_add_entry(&backend, 0, 112233, 0, 0);
	map_delete_elem(&cilium_lb6_reverse_sk, &lru_key);
	st6_valid = false;

	test_init();

	memcpy(addr.user_ip6, &svc_a, 16);
	addr.user_port = SVC_PORT_A;
	ret = __sock6_xlate_fwd(&addr, false, true);
	assert(ret == 0);
	assert(!memcmp(addr.user_ip6, &backend, 16));
	assert(addr.user_port == BACKEND_PORT);
	assert(st6_valid);
	assert(ipv6_addr_equals(&st6.address, &svc_a));
	assert(st6.port == SVC_PORT_A);
	assert(st6.rev_nat_index == REVNAT_A);
	assert(ipv6_addr_equals(&st6.backend_address, &backend));
	assert(st6.backend_port == BACKEND_PORT);
	assert(map_lookup_elem(&cilium_lb6_reverse_sk, &lru_key));
	sk.dst_port = BACKEND_PORT;

	ret = rev6(&addr, &backend, RECVMSG);
	assert(ret == 0);
	assert(!memcmp(addr.user_ip6, &svc_a, 16));
	assert(addr.user_port == SVC_PORT_A);
	map_delete_elem(&cilium_lb6_reverse_sk, &lru_key);
	ret = rev6(&addr, &backend, RECVMSG);
	assert(ret == 0);
	assert(!memcmp(addr.user_ip6, &svc_a, 16));
	assert(addr.user_port == SVC_PORT_A);
	ret = rev6(&addr, &backend, GETPEERNAME);
	assert(ret == 0);
	assert(!memcmp(addr.user_ip6, &svc_a, 16));
	assert(addr.user_port == SVC_PORT_A);

	memcpy(addr.user_ip6, &svc_b, 16);
	addr.user_port = SVC_PORT_B;
	ret = __sock6_xlate_fwd(&addr, true, false);
	assert(ret == 0);
	assert(st6_valid);
	assert(ipv6_addr_equals(&st6.address, &svc_a));
	ret = rev6(&addr, &backend, RECVMSG);
	assert(ret == 0);
	assert(!memcmp(addr.user_ip6, &svc_b, 16));
	assert(addr.user_port == SVC_PORT_B);
	ret = rev6(&addr, &backend, GETPEERNAME);
	assert(ret == 0);
	assert(!memcmp(addr.user_ip6, &svc_a, 16));
	assert(addr.user_port == SVC_PORT_A);

	sk.dst_port = 0;
	memcpy(addr.user_ip6, &svc_b, 16);
	addr.user_port = SVC_PORT_B;
	ret = __sock6_xlate_fwd(&addr, true, false);
	assert(ret == 0);
	assert(st6_valid);
	assert(ipv6_addr_equals(&st6.address, &svc_a));
	ret = rev6(&addr, &backend, RECVMSG);
	assert(ret == 0);
	assert(!memcmp(addr.user_ip6, &svc_b, 16));
	assert(addr.user_port == SVC_PORT_B);

	map_delete_elem(&cilium_lb6_reverse_sk, &lru_key);
	ret = rev6(&addr, &backend, RECVMSG);
	assert(ret == -ENXIO);
	assert(!memcmp(addr.user_ip6, &backend, 16));
	assert(addr.user_port == BACKEND_PORT);
	memcpy(addr.user_ip6, &svc_b, 16);
	addr.user_port = SVC_PORT_B;
	ret = __sock6_xlate_fwd(&addr, true, false);
	assert(ret == 0);

	lb_v6_add_service(&svc_a, SVC_PORT_A, IPPROTO_UDP, 1, REVNAT_OTHER);
	ret = rev6(&addr, &backend, RECVMSG);
	assert(ret == 0);
	assert(!memcmp(addr.user_ip6, &svc_b, 16));
	assert(addr.user_port == SVC_PORT_B);
	assert(map_lookup_elem(&cilium_lb6_reverse_sk, &lru_key));

	sk.dst_port = BACKEND_PORT;
	ret = rev6(&addr, &backend, GETPEERNAME);
	assert(ret == 0);
	assert(!memcmp(addr.user_ip6, &svc_b, 16));
	assert(addr.user_port == SVC_PORT_B);
	assert(!st6_valid);
	lru = map_lookup_elem(&cilium_lb6_reverse_sk, &lru_key);
	assert(lru);
	assert(lru->rev_nat_index == REVNAT_B);

	lb_v6_add_service(&svc_b, SVC_PORT_B, IPPROTO_UDP, 1, REVNAT_OTHER);
	ret = rev6(&addr, &backend, RECVMSG);
	assert(ret == -ENXIO);
	assert(!memcmp(addr.user_ip6, &backend, 16));
	assert(addr.user_port == BACKEND_PORT);
	assert(!map_lookup_elem(&cilium_lb6_reverse_sk, &lru_key));

	lb_v6_add_service(&svc_a, SVC_PORT_A, IPPROTO_UDP, 1, REVNAT_A);
	lb_v6_add_service(&svc_b, SVC_PORT_B, IPPROTO_UDP, 1, REVNAT_B);
	memcpy(addr.user_ip6, &svc_b, 16);
	addr.user_port = SVC_PORT_B;
	ret = __sock6_xlate_fwd(&addr, true, false);
	assert(ret == 0);
	st6_valid = true;
	memcpy(&st6.address, &svc_a, sizeof(svc_a));
	st6.port = SVC_PORT_A;
	st6.rev_nat_index = REVNAT_A;
	memcpy(&st6.backend_address, &other, sizeof(other));
	st6.backend_port = BACKEND_PORT;
	ret = rev6(&addr, &backend, GETPEERNAME);
	assert(ret == 0);
	assert(!memcmp(addr.user_ip6, &svc_b, 16));
	assert(addr.user_port == SVC_PORT_B);
	assert(st6_valid);

	test_finish();
}

#define NODEPORT	bpf_htons(30080)
#define REVNAT_NODEPORT	3

static __always_inline int connect4(struct bpf_sock_addr *addr, __be32 ip,
				    __be16 port)
{
	addr->user_ip4 = ip;
	addr->user_port = port;
	return __sock4_xlate_fwd(addr, addr, false, true);
}

/* connect() of an IPv6 socket to an IPv4-mapped address. */
static __always_inline int connect46(struct bpf_sock_addr *addr, __be32 ip,
				     __be16 port)
{
	addr->user_ip6[0] = 0;
	addr->user_ip6[1] = 0;
	addr->user_ip6[2] = bpf_htonl(0xffff);
	addr->user_ip6[3] = ip;
	addr->user_port = port;
	return __sock6_xlate_fwd(addr, false, true);
}

static __always_inline int connect6(struct bpf_sock_addr *addr,
				    const union v6addr *ip, __be16 port)
{
	memcpy(addr->user_ip6, ip, 16);
	addr->user_port = port;
	return __sock6_xlate_fwd(addr, false, true);
}

/* connect() drops the reverse NAT state of the socket's previous connection
 * before translating. A socket that reached a backend through a service and
 * then connects to it directly must neither report the service nor match it
 * in socket termination, whether or not it has storage. A connect() through
 * a service whose backend has the service's own address and port must keep
 * the state it records.
 */
CHECK("xdp", "sock4_revnat_direct_reconnect")
int test_sock4_revnat_direct_reconnect(__maybe_unused struct xdp_md *ctx)
{
	struct bpf_sock sk = {};
	struct bpf_sock_addr addr = {
		.protocol = IPPROTO_UDP,
		.sk = &sk,
	};
	struct ipv4_revnat_tuple lru_x = {
		.cookie = 0,
		.address = v4_pod_one,
		.port = BACKEND_PORT,
	};
	struct ipv4_revnat_tuple lru_y = {
		.cookie = 0,
		.address = v4_pod_two,
		.port = BACKEND_PORT,
	};
	struct ipv4_revnat_tuple lru_node = {
		.cookie = 0,
		.address = v4_node_one,
		.port = NODEPORT,
	};
	int ret;

	/* A fronts backend X, B fronts backend Y. */
	lb_v4_add_service(v4_svc_one, SVC_PORT_A, IPPROTO_UDP, 1, REVNAT_A);
	lb_v4_add_backend(v4_svc_one, SVC_PORT_A, 1, 124, v4_pod_one,
			  BACKEND_PORT, IPPROTO_UDP, 0);
	lb_v4_add_service(v4_svc_two, SVC_PORT_B, IPPROTO_UDP, 1, REVNAT_B);
	lb_v4_add_backend(v4_svc_two, SVC_PORT_B, 1, 125, v4_pod_two,
			  BACKEND_PORT, IPPROTO_UDP, 0);
	ipcache_v4_add_entry(v4_pod_one, 0, 112233, 0, 0);
	ipcache_v4_add_entry(v4_pod_two, 0, 112233, 0, 0);
	map_delete_elem(&cilium_lb4_reverse_sk, &lru_x);
	map_delete_elem(&cilium_lb4_reverse_sk, &lru_y);
	st4_valid = false;

	test_init();

	/* connect() to A, connect(AF_UNSPEC), then connect() to X directly. */
	ret = connect4(&addr, v4_svc_one, SVC_PORT_A);
	assert(ret == 0);
	assert(addr.user_ip4 == v4_pod_one);
	assert(st4_valid);
	assert(map_lookup_elem(&cilium_lb4_reverse_sk, &lru_x));
	ret = connect4(&addr, v4_pod_one, BACKEND_PORT);
	assert(ret == -ENXIO);
	assert(addr.user_ip4 == v4_pod_one);
	assert(addr.user_port == BACKEND_PORT);
	assert(!st4_valid);
	assert(!map_lookup_elem(&cilium_lb4_reverse_sk, &lru_x));

	/* Neither getpeername() nor recvmsg() report A any more. */
	sk.dst_ip4 = v4_pod_one;
	sk.dst_port = BACKEND_PORT;
	ret = rev4(&addr, GETPEERNAME);
	assert(ret == -ENXIO);
	assert(addr.user_ip4 == v4_pod_one);
	assert(addr.user_port == BACKEND_PORT);
	ret = rev4(&addr, RECVMSG);
	assert(ret == -ENXIO);
	assert(addr.user_ip4 == v4_pod_one);

	/* The same for a socket without storage, e.g. one that connected to A
	 * before the upgrade, or failed to allocate its storage.
	 */
	ret = connect4(&addr, v4_svc_one, SVC_PORT_A);
	assert(ret == 0);
	st4_valid = false;
	ret = connect4(&addr, v4_pod_one, BACKEND_PORT);
	assert(ret == -ENXIO);
	assert(!map_lookup_elem(&cilium_lb4_reverse_sk, &lru_x));

	/* connect() to A, then to B, then directly to Y and to X. The storage
	 * only describes the last connection, while the legacy map keeps an
	 * entry per backend.
	 */
	ret = connect4(&addr, v4_svc_one, SVC_PORT_A);
	assert(ret == 0);
	ret = connect4(&addr, v4_svc_two, SVC_PORT_B);
	assert(ret == 0);
	assert(addr.user_ip4 == v4_pod_two);
	assert(st4_valid);
	assert(st4.address == v4_svc_two);
	assert(map_lookup_elem(&cilium_lb4_reverse_sk, &lru_x));
	assert(map_lookup_elem(&cilium_lb4_reverse_sk, &lru_y));
	ret = connect4(&addr, v4_pod_two, BACKEND_PORT);
	assert(ret == -ENXIO);
	assert(!st4_valid);
	assert(!map_lookup_elem(&cilium_lb4_reverse_sk, &lru_y));
	ret = connect4(&addr, v4_pod_one, BACKEND_PORT);
	assert(ret == -ENXIO);
	assert(!map_lookup_elem(&cilium_lb4_reverse_sk, &lru_x));
	ret = rev4(&addr, GETPEERNAME);
	assert(ret == -ENXIO);
	assert(addr.user_ip4 == v4_pod_one);

	/* A NodePort whose host-network backend listens on the same address and
	 * port: connect() is translated without changing the destination, and
	 * keeps the state it records.
	 */
	lb_v4_add_service_with_flags(v4_node_one, NODEPORT, IPPROTO_UDP, 1,
				     REVNAT_NODEPORT, SVC_FLAG_NODEPORT, 0);
	lb_v4_add_backend(v4_node_one, NODEPORT, 1, 126, v4_node_one, NODEPORT,
			  IPPROTO_UDP, 0);
	ipcache_v4_add_entry(v4_node_one, 0, HOST_ID, 0, 0);
	map_delete_elem(&cilium_lb4_reverse_sk, &lru_node);
	ret = connect4(&addr, v4_node_one, NODEPORT);
	assert(ret == 0);
	assert(addr.user_ip4 == v4_node_one);
	assert(addr.user_port == NODEPORT);
	assert(st4_valid);
	assert(st4.rev_nat_index == REVNAT_NODEPORT);
	assert(map_lookup_elem(&cilium_lb4_reverse_sk, &lru_node));

	/* An IPv4-mapped IPv6 socket uses the IPv4 state. */
	memset(&addr, 0, sizeof(addr));
	addr.protocol = IPPROTO_UDP;
	addr.sk = &sk;
	ret = connect46(&addr, v4_svc_one, SVC_PORT_A);
	assert(ret == 0);
	assert(addr.user_ip6[3] == v4_pod_one);
	assert(st4_valid);
	assert(st4.address == v4_svc_one);
	assert(map_lookup_elem(&cilium_lb4_reverse_sk, &lru_x));
	ret = connect46(&addr, v4_pod_one, BACKEND_PORT);
	assert(ret == -ENXIO);
	assert(addr.user_ip6[3] == v4_pod_one);
	assert(addr.user_port == BACKEND_PORT);
	assert(!st4_valid);
	assert(!map_lookup_elem(&cilium_lb4_reverse_sk, &lru_x));

	test_finish();
}

/* See test_sock4_revnat_direct_reconnect. */
CHECK("xdp", "sock6_revnat_direct_reconnect")
int test_sock6_revnat_direct_reconnect(__maybe_unused struct xdp_md *ctx)
{
	union v6addr svc_a = {}, svc_b = {}, backend_x = {}, backend_y = {};
	union v6addr node = {};
	struct bpf_sock sk = {};
	struct bpf_sock_addr addr = {
		.protocol = IPPROTO_UDP,
		.sk = &sk,
	};
	struct ipv6_revnat_tuple lru_x = {
		.cookie = 0,
		.port = BACKEND_PORT,
	};
	struct ipv6_revnat_tuple lru_y = {
		.cookie = 0,
		.port = BACKEND_PORT,
	};
	struct ipv6_revnat_tuple lru_node = {
		.cookie = 0,
		.port = NODEPORT,
	};
	int ret;

	memcpy(svc_a.addr, (void *)v6_node_one, 16);
	memcpy(svc_b.addr, (void *)v6_node_two, 16);
	memcpy(backend_x.addr, (void *)v6_pod_one, 16);
	memcpy(backend_y.addr, (void *)v6_pod_two, 16);
	memcpy(node.addr, (void *)v6_node_three, 16);
	memcpy(&lru_x.address, &backend_x, sizeof(backend_x));
	memcpy(&lru_y.address, &backend_y, sizeof(backend_y));
	memcpy(&lru_node.address, &node, sizeof(node));

	lb_v6_add_service(&svc_a, SVC_PORT_A, IPPROTO_UDP, 1, REVNAT_A);
	lb_v6_add_backend(&svc_a, SVC_PORT_A, 1, 124, &backend_x, BACKEND_PORT,
			  IPPROTO_UDP, 0);
	lb_v6_add_service(&svc_b, SVC_PORT_B, IPPROTO_UDP, 1, REVNAT_B);
	lb_v6_add_backend(&svc_b, SVC_PORT_B, 1, 125, &backend_y, BACKEND_PORT,
			  IPPROTO_UDP, 0);
	ipcache_v6_add_entry(&backend_x, 0, 112233, 0, 0);
	ipcache_v6_add_entry(&backend_y, 0, 112233, 0, 0);
	map_delete_elem(&cilium_lb6_reverse_sk, &lru_x);
	map_delete_elem(&cilium_lb6_reverse_sk, &lru_y);
	st6_valid = false;

	test_init();

	ret = connect6(&addr, &svc_a, SVC_PORT_A);
	assert(ret == 0);
	assert(!memcmp(addr.user_ip6, &backend_x, 16));
	assert(st6_valid);
	assert(map_lookup_elem(&cilium_lb6_reverse_sk, &lru_x));
	ret = connect6(&addr, &backend_x, BACKEND_PORT);
	assert(ret == -ENXIO);
	assert(!memcmp(addr.user_ip6, &backend_x, 16));
	assert(addr.user_port == BACKEND_PORT);
	assert(!st6_valid);
	assert(!map_lookup_elem(&cilium_lb6_reverse_sk, &lru_x));

	sk.dst_port = BACKEND_PORT;
	ret = rev6(&addr, &backend_x, GETPEERNAME);
	assert(ret == -ENXIO);
	assert(!memcmp(addr.user_ip6, &backend_x, 16));
	assert(addr.user_port == BACKEND_PORT);
	ret = rev6(&addr, &backend_x, RECVMSG);
	assert(ret == -ENXIO);
	assert(!memcmp(addr.user_ip6, &backend_x, 16));

	ret = connect6(&addr, &svc_a, SVC_PORT_A);
	assert(ret == 0);
	st6_valid = false;
	ret = connect6(&addr, &backend_x, BACKEND_PORT);
	assert(ret == -ENXIO);
	assert(!map_lookup_elem(&cilium_lb6_reverse_sk, &lru_x));

	ret = connect6(&addr, &svc_a, SVC_PORT_A);
	assert(ret == 0);
	ret = connect6(&addr, &svc_b, SVC_PORT_B);
	assert(ret == 0);
	assert(!memcmp(addr.user_ip6, &backend_y, 16));
	assert(st6_valid);
	assert(ipv6_addr_equals(&st6.address, &svc_b));
	assert(map_lookup_elem(&cilium_lb6_reverse_sk, &lru_x));
	assert(map_lookup_elem(&cilium_lb6_reverse_sk, &lru_y));
	ret = connect6(&addr, &backend_y, BACKEND_PORT);
	assert(ret == -ENXIO);
	assert(!st6_valid);
	assert(!map_lookup_elem(&cilium_lb6_reverse_sk, &lru_y));
	ret = connect6(&addr, &backend_x, BACKEND_PORT);
	assert(ret == -ENXIO);
	assert(!map_lookup_elem(&cilium_lb6_reverse_sk, &lru_x));
	ret = rev6(&addr, &backend_x, GETPEERNAME);
	assert(ret == -ENXIO);
	assert(!memcmp(addr.user_ip6, &backend_x, 16));

	lb_v6_add_service_with_flags(&node, NODEPORT, IPPROTO_UDP, 1,
				     REVNAT_NODEPORT, SVC_FLAG_NODEPORT, 0);
	lb_v6_add_backend(&node, NODEPORT, 1, 126, &node, NODEPORT,
			  IPPROTO_UDP, 0);
	ipcache_v6_add_entry(&node, 0, HOST_ID, 0, 0);
	map_delete_elem(&cilium_lb6_reverse_sk, &lru_node);
	ret = connect6(&addr, &node, NODEPORT);
	assert(ret == 0);
	assert(!memcmp(addr.user_ip6, &node, 16));
	assert(addr.user_port == NODEPORT);
	assert(st6_valid);
	assert(st6.rev_nat_index == REVNAT_NODEPORT);
	assert(map_lookup_elem(&cilium_lb6_reverse_sk, &lru_node));

	test_finish();
}
