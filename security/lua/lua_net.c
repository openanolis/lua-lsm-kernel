/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Lua based LSM
 *
 * Copyright (C) 2025 The Alibaba Cloud Linux Authors.
 */

#include "debug.h"
#include <linux/printk.h>
#include <linux/security.h>
#include <linux/inet.h>
#include <net/inet_sock.h>
#include <uapi/linux/in.h>
#include <uapi/linux/in6.h>
#include <uapi/linux/un.h>
#include <linux/lua.h>
#include <linux/lualib.h>
#include <linux/lauxlib.h>
#include "lsm.h"
#include "auxlib.h"
#include "kvcache.h"
#include "lua_object.h"

static const char *family_tostring(sa_family_t sa_family)
{
	const char *family = NULL;
	switch (sa_family) {
	case AF_UNSPEC:		family = "unspec";	break;
	case AF_INET:		family = "inet";	break;
	case AF_INET6:		family = "inet6";	break;
	case AF_UNIX:		family = "unix";	break;
	case AF_NETLINK:	family = "netlink";	break;
	case AF_PACKET:		family = "packet";	break;
	case AF_KEY:		family = "key";		break;
	case AF_APPLETALK:	family = "appletalk";	break;
	case AF_ALG:		family = "alg";		break;
	case AF_NFC:		family = "nfc";		break;
	case AF_VSOCK:		family = "vsock";	break;
	case AF_KCM:		family = "kcm";		break;
	case AF_SMC:		family = "smc";		break;
	}
	return family;
}

/*********************************** sock ***********************************/

static int net_sock_socket(lua_State *L)
{
	struct sock *sk = tosock(L, 1);
	*newsocket(L) = sk->sk_socket;
	return 1;
}

static int net_sock_suites(lua_State *L)
{
	struct sock *sk = tosock(L, 1);
	const char *family = "unknown", *type = "unknown", *protocol = "unknown";
	int nres = 0;
	if (lua_gettop(L) >= 2) {
		if (!lua_toboolean(L, 2))
			family = NULL;
		if (!lua_toboolean(L, 3))
			type = NULL;
		if (!lua_toboolean(L, 4))
			protocol = NULL;
	}
	if (family) {
		family = family_tostring(sk->sk_family);
		if (family == NULL)
			family = "unknown";
		lua_pushstring(L, family);
		nres += 1;
	}
	if (type) {
		switch (sk->sk_type) {
		case SOCK_STREAM:	type = "stream";	break;
		case SOCK_DGRAM:	type = "dgram";		break;
		case SOCK_RAW:		type = "raw";		break;
		case SOCK_RDM:		type = "rdm";		break;
		case SOCK_SEQPACKET:	type = "seqpacket";	break;
		case SOCK_DCCP:		type = "dccp";		break;
		case SOCK_PACKET:	type = "packet";	break;
		}
		lua_pushstring(L, type);
		nres += 1;
	}
	if (protocol) {
		switch (sk->sk_protocol) {
		case IPPROTO_IP:	protocol = "ip";	break;
		case IPPROTO_ICMP:	protocol = "icmp";	break;
		case IPPROTO_IGMP:	protocol = "igmp";	break;
		case IPPROTO_TCP:	protocol = "tcp";	break;
		case IPPROTO_EGP:	protocol = "egp";	break;
		case IPPROTO_UDP:	protocol = "udp";	break;
		case IPPROTO_DCCP:	protocol = "dccp";	break;
		case IPPROTO_IPV6:	protocol = "ipv6";	break;
		case IPPROTO_ESP:	protocol = "esp";	break;
		case IPPROTO_L2TP:	protocol = "l2tp";	break;
		case IPPROTO_SCTP:	protocol = "sctp";	break;
		case IPPROTO_UDPLITE:	protocol = "udplite";	break;
		case IPPROTO_RAW:	protocol = "raw";	break;
		case IPPROTO_SMC:	protocol = "smc";	break;
		case IPPROTO_MPTCP:	protocol = "mptcp";	break;
		}
		lua_pushstring(L, protocol);
		nres += 1;
	}
	return nres;
}

static int net_sock_listener(lua_State *L)
{
	struct sock *sk = tosock(L, 1);
	int time_wait = lua_toboolean(L, 2);
	lua_pushboolean(L, time_wait ? sk_listener_or_tw(sk) : sk_listener(sk));
	return 1;
}

#define SOCK_BOOL_DEF(name)						\
	static int net_sock_is_ ## name(lua_State *L)			\
	{								\
		struct sock *sk = tosock(L, 1);				\
		lua_pushboolean(L, sk_is_ ## name(sk));			\
		return 1;						\
	}

SOCK_BOOL_DEF(inet)
SOCK_BOOL_DEF(tcp)
SOCK_BOOL_DEF(udp)
SOCK_BOOL_DEF(stream_unix)
SOCK_BOOL_DEF(vsock)

static const luaL_Reg sock_meth[] = {
	{ "socket",		net_sock_socket		},
	{ "suites",		net_sock_suites		},
	{ "listener",		net_sock_listener	},
	{ "is_inet",		net_sock_is_inet	},
	{ "is_tcp",		net_sock_is_tcp		},
	{ "is_udp",		net_sock_is_udp		},
	{ "is_stream_unix",	net_sock_is_stream_unix	},
	{ "is_vsock",		net_sock_is_vsock	},
	{ NULL, NULL }
};

/********************************** socket **********************************/

static int net_socket_release(lua_State *L)
{
	struct socket **sockp = tosocketp(L, 1);
	if (*sockp) {
		sock_release(*sockp);
		*sockp = NULL;
	}
	return 0;
}

static int net_socket_sock(lua_State *L)
{
	struct socket *sock = tosocket(L, 1);
	*newsock(L) = sock->sk;
	return 1;
}

static int net_socket_inode(lua_State *L)
{
	struct socket *sock = tosocket(L, 1);
	*newinode(L) = SOCK_INODE(sock);
	return 1;
}

static const luaL_Reg socket_meth[] = {
	{ "release",	net_socket_release	},
	{ "sock",	net_socket_sock		},
	{ "inode",	net_socket_inode	},
	{ NULL, NULL }
};

/********************************** sk_buff *********************************/

static int net_skb_sock(lua_State *L)
{
	struct sk_buff *skb = toskb(L, 1);
	*newsock(L) = skb->sk;
	return 1;
}

static int net_skb_full_sk(lua_State *L)
{
	struct sk_buff *skb = toskb(L, 1);
	*newsock(L) = skb_to_full_sk(skb);
	return 1;
}

static int net_skb_protocol(lua_State *L)
{
	struct sk_buff *skb = toskb(L, 1);
	const char *protocol = "unknown";
	switch (skb->protocol) {
	case htons(ETH_P_LOOP):	protocol = "loop";	break;
	case htons(ETH_P_IP):	protocol = "ip";	break;
	case htons(ETH_P_IPV6):	protocol = "ipv6";	break;
	case htons(ETH_P_ARP):	protocol = "arp";	break;
	case htons(ETH_P_RARP):	protocol = "rarp";	break;
	}
	lua_pushstring(L, protocol);
	return 1;
}

static int net_skb_iif(lua_State *L)
{
	struct sk_buff *skb = toskb(L, 1);
	lua_pushinteger(L, skb->skb_iif);
	return 1;
}

static int net_skb_secmark(lua_State *L)
{
	struct sk_buff *skb = toskb(L, 1);
	lua_pushinteger(L, skb->secmark);
	return 1;
}

static const luaL_Reg skb_meth[] = {
	{ "sock",	net_skb_sock		},
	{ "full_sk",	net_skb_full_sk		},
	{ "protocol",	net_skb_protocol	},
	{ "iif",	net_skb_iif		},
	{ "secmark",	net_skb_secmark		},
	{ NULL, NULL }
};

/********************************** sockaddr ********************************/

static int sockaddr_family(lua_State *L)
{
	struct sockaddr *sa = tosockaddr(L, 1);
	const char *family = family_tostring(sa->sa_family);
	if (family == NULL)
		family = "unknown";
	lua_pushstring(L, family);
	return 1;
}

static int sockaddr_addrs(lua_State *L)
{
	struct sockaddr *sa = tosockaddr(L, 1);
	int readable = lua_toboolean(L, 2);
	char buffer[128];
	int l;
	switch (sa->sa_family) {
	case AF_INET:
		lua_pushstring(L, "inet");
		if (readable) {
			l = snprintf(buffer, sizeof(buffer), "%pISc", sa);
			lua_pushlstring(L, buffer, l);
		} else {
			lua_pushinteger(L, ((struct sockaddr_in *)sa)->sin_addr.s_addr);
		}
		lua_pushinteger(L, ntohs(((struct sockaddr_in *)sa)->sin_port));
		return 3;
	case AF_INET6:
		lua_pushstring(L, "inet6");
		if (readable) {
			l = snprintf(buffer, sizeof(buffer), "%pISc", sa);
			lua_pushlstring(L, buffer, l);
		} else {
			lua_pushlstring(L, ((struct sockaddr_in6 *)sa)->sin6_addr.s6_addr,
				sizeof(((struct sockaddr_in6 *)sa)->sin6_addr.s6_addr));
		}
		lua_pushinteger(L, ntohs(((struct sockaddr_in6 *)sa)->sin6_port));
		return 3;
	case AF_UNIX:
		lua_pushstring(L, "unix");
		lua_pushstring(L, ((struct sockaddr_un *)sa)->sun_path);
		return 2;
	}
	return 0;
}

static int meth_sockaddr_tostring(lua_State *L)
{
	struct sockaddr *sa = tosockaddr(L, 1);
	char buffer[128];
	int l;
	switch (sa->sa_family) {
	case AF_INET:
		l = snprintf(buffer, sizeof(buffer), "sa.inet: %pISpc", sa);
		lua_pushlstring(L, buffer, l);
		break;
	case AF_INET6:
		l = snprintf(buffer, sizeof(buffer), "sa.inet6: %pISpc", sa);
		lua_pushlstring(L, buffer, l);
		break;
	case AF_UNIX:
		lua_pushfstring(L, "sa.unix: %s", ((struct sockaddr_un *)sa)->sun_path);
		break;
	case AF_NETLINK:
		lua_pushfstring(L, "sa.netlink: %d", ((struct sockaddr_nl *)sa)->nl_pid);
		break;
	default:
		lua_pushfstring(L, "sa.%s", family_tostring(sa->sa_family) ?: "(unknown)");
		break;
	}
	return 1;
}

static const luaL_Reg sockaddr_meth[] = {
	{ "family",	sockaddr_family		},
	{ "addrs",	sockaddr_addrs		},
	{ "__tostring",	meth_sockaddr_tostring	},
	{ NULL, NULL }
};

/************************************ lib ***********************************/

static int net_sock_alloc(lua_State *L)
{
	struct socket **sockp = newsocket(L);
	*sockp = sock_alloc();
	if (*sockp == NULL)
		return 0;
	return 1;
}

#define INET_HN_DEFINE(name)						\
	static int net_ ## name(lua_State *L)				\
	{								\
		lua_Integer n = luaL_checkinteger(L, 1);		\
		lua_pushinteger(L, (lua_Integer)name(n));		\
		return 1;						\
	}

INET_HN_DEFINE(htonl)
INET_HN_DEFINE(ntohl)
INET_HN_DEFINE(htons)
INET_HN_DEFINE(ntohs)

static int net_in_aton(lua_State *L)
{
	const char *s = luaL_checkstring(L, 1);
	lua_pushinteger(L, in_aton(s));
	return 1;
}

static int net_in4_pton(lua_State *L)
{
	size_t len;
	const char *s = luaL_checklstring(L, 1, &len);
	__be32 addr;
	if (in4_pton(s, (int)len, (u8 *)&addr, '\n', NULL))
		lua_pushinteger(L, addr);
	else
		lua_pushnil(L);
	return 1;
}

static int net_in6_pton(lua_State *L)
{
	size_t len;
	const char *s = luaL_checklstring(L, 1, &len);
	__u8 addr[16];
	if (in6_pton(s, (int)len, (u8 *)addr, '\n', NULL))
		lua_pushlstring(L, addr, sizeof(addr));
	else
		lua_pushnil(L);
	return 1;
}

static const luaL_Reg netlib[] = {
	{ "sock_alloc",	net_sock_alloc	},
	{ "htonl",	net_htonl	},
	{ "ntohl",	net_ntohl	},
	{ "htons",	net_htons	},
	{ "ntohs",	net_ntohs	},
	{ "in_aton",	net_in_aton	},
	{ "in4_pton",	net_in4_pton	},
	{ "in6_pton",	net_in6_pton	},
	{ NULL, NULL }
};


LUALIB_API int luaopen_net(lua_State *L)
{
	luaL_newlib(L, netlib);

	create_sock_meta(L, sock_meth, NULL);
	create_socket_meta(L, socket_meth, NULL);
	create_skb_meta(L, skb_meth, NULL);
	create_sockaddr_meta(L, sockaddr_meth, NULL);

	return 1;
}
