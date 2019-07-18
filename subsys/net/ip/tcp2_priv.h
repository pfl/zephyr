/*
 * Copyright (c) 2018-2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "tp.h"

#define PKT_DST 0
#define PKT_SRC 1

#define is(_a, _b) (strcmp((_a), (_b)) == 0)

#define tcp_dbg(fmt, args...) printk("%s: " fmt "\n", __func__, ## args)
#define tcp_err(fmt, args...) do {				\
	printk("%s: Error: " fmt "\n", __func__, ## args);	\
	k_oops();						\
} while (0)

#define tcp_assert(cond, fmt, args...) do {			\
	if ((cond) == false) {					\
		printk("%s: Assertion failed: %s, " fmt "\n",	\
			__func__, #cond, ## args);		\
		k_oops();					\
	}							\
} while (0)

#define th_seq(_x) ntohl((_x)->th_seq)
#define th_ack(_x) ntohl((_x)->th_ack)
#define ip_get(_x) ((struct net_ipv4_hdr *) net_pkt_ip_data((_x)))
#define th_get(_x) ((_x) ? ((struct tcphdr *) (ip_get(_x) + 1)) : NULL)

#if IS_ENABLED(CONFIG_NET_TP)
#define tcp_malloc(_size) tp_malloc(_size, tp_basename(__FILE__), __LINE__)
#define tcp_calloc(_nmemb, _size) \
	tp_calloc(_nmemb, _size, tp_basename(__FILE__), __LINE__)
#define tcp_free(_ptr) tp_free(_ptr, tp_basename(__FILE__), __LINE__, __func__)
#else
#define tcp_malloc(_size) k_malloc(_size)
#define tcp_calloc(_nmemb, _size) k_calloc(_nmemb, _size)
#define tcp_free(_ptr) k_free(_ptr)
#endif

#if IS_ENABLED(CONFIG_NET_TP)
#define tcp_nbuf_alloc(_pool, _len) \
	tp_nbuf_alloc(_pool, _len, tp_basename(__FILE__), __LINE__, __func__)
#define tcp_nbuf_unref(_nbuf) \
	tp_nbuf_unref(_nbuf, tp_basename(__FILE__), __LINE__, __func__)
#else
#define tcp_nbuf_alloc(_pool, _len) net_buf_alloc_len(_pool, _len, K_NO_WAIT)
#define tcp_nbuf_unref(_nbuf) net_buf_unref(_nbuf)
#endif

#if IS_ENABLED(CONFIG_NET_TP)
#define tcp_pkt_alloc(_len) tp_pkt_alloc(_len, tp_basename(__FILE__), __LINE__)
#define tcp_pkt_clone(_pkt) tp_pkt_clone(_pkt, tp_basename(__FILE__), __LINE__)
#define tcp_pkt_unref(_pkt) tp_pkt_unref(_pkt, tp_basename(__FILE__), __LINE__)
#else
static struct net_pkt *tcp_pkt_alloc(size_t len)
{
	struct net_pkt *pkt = net_pkt_alloc(K_NO_WAIT);
	struct net_buf *nbuf = net_pkt_get_frag(pkt, K_NO_WAIT);

	tcp_assert(pkt && nbuf, "");

	pkt->family = AF_INET;

	net_buf_add(nbuf, len);
	net_pkt_frag_insert(pkt, nbuf);

	return pkt;
}
#define tcp_pkt_clone(_pkt) net_pkt_clone(_pkt, K_NO_WAIT)
#define tcp_pkt_unref(_pkt) net_pkt_unref(_pkt)
#endif

#if IS_ENABLED(CONFIG_NET_TP)
#define conn_seq(_conn, _req) \
	tp_seq_track(TP_SEQ, &(_conn)->seq, (_req), tp_basename(__FILE__), \
			__LINE__, __func__)
#define conn_ack(_conn, _req) \
	tp_seq_track(TP_ACK, &(_conn)->ack, (_req), tp_basename(__FILE__), \
			__LINE__, __func__)
#else
#define conn_seq(_conn, _req) (_conn)->seq += (_req)
#define conn_ack(_conn, _req) (_conn)->ack += (_req)
#endif

struct tcphdr {
	u16_t th_sport;
	u16_t th_dport;
	u32_t th_seq;
	u32_t th_ack;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	u8_t th_x2:4;	/* unused */
	u8_t th_off:4;	/* data offset */
#endif
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	u8_t th_off:4;
	u8_t th_x2:4;
#endif
	u8_t th_flags;
	u16_t th_win;
	u16_t th_sum;
	u16_t th_urp;
};

enum th_flags {
	FIN = 1,
	SYN = 1 << 1,
	RST = 1 << 2,
	PSH = 1 << 3,
	ACK = 1 << 4,
	URG = 1 << 5,
};

enum tcp_state {
	TCP_NONE = 0,
	TCP_LISTEN,
	TCP_SYN_SENT,
	TCP_SYN_RECEIVED,
	TCP_ESTABLISHED,
	TCP_FIN_WAIT1,
	TCP_FIN_WAIT2,
	TCP_CLOSE_WAIT,
	TCP_CLOSING,
	TCP_LAST_ACK,
	TCP_TIME_WAIT,
	TCP_CLOSED
};

enum tcp_conn_kind {
	TCP_PASSIVE = 0,
	TCP_ACTIVE
};

struct tcp_win { /* TCP window */
	char *name;
	size_t len;
	sys_slist_t bufs;
};

union tcp_endpoint {
	struct sockaddr sa;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
};

struct tcp { /* TCP connection */
	sys_snode_t next;
	enum tcp_state state;
	enum tcp_conn_kind kind;
	int fd;
	u32_t seq;
	u32_t ack;
	union tcp_endpoint *src;
	union tcp_endpoint *dst;
	u16_t win;
	struct tcp_win *rcv;
	struct tcp_win *snd;
	sys_slist_t retr;
	int retries; /* number of retransmissions */
	struct k_timer timer;
	struct net_if *iface;
};

/*
 * The following macros assume the presense of in the local context:
 *  - struct tcphdr *th: pointer to the TCP header
 *  - struct tcp *conn: pointer to the TCP connection
 */
#define SEQ(_cond) (th && (th_seq(th) _cond conn->ack))

static bool th_is_present(struct tcphdr *th, const u8_t fl, bool cond)
{
	bool present = false;

	if (th && cond && (fl & th->th_flags)) {
		th->th_flags &= ~fl;
		present = true;
	}

	return present;
}

#define ON(_fl, _cond...) \
	th_is_present(th, _fl, strlen("" #_cond) ? _cond : true)

static bool th_is_equal(struct tcphdr *th, const u8_t fl, bool cond)
{
	bool equal = false;

	if (th && cond && (fl == th->th_flags)) {
		th->th_flags &= ~fl;
		equal = true;
	}

	return equal;
}

#define EQ(_fl, _cond...) \
	th_is_equal(th, _fl, strlen("" #_cond) ? _cond : true)

