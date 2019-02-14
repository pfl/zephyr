/*
 * Copyright (c) 2018-2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * This implementation of the TCP protocol is a proof of concept
 * of the following:
 *
 * Goal
 *
 * - Verifiable with the open source protocol test tools
 *
 * Implementation
 *
 * - State machine
 * - Separation of TCP control, data and retransmission mechanisms
 * - Whitelisting approach
 *
 * Sanity Check Suite
 *
 * Along with it, a TTCN-3 based sanity check suite is being developed:
 *
 * https://github.com/intel/net-test-suites/blob/master/src/tcp2_check.ttcnpp
 *
 * The sanity check is able to verify:
 *
 * - Control flow (active, passive connection establishment, termination)
 * - Retransmission
 * - Data
 *
 * To run the sanity check:
 *
 * 1. Compile and start the net-test-tools:
 *     https://github.com/intel/net-test-tools
 * 2. Compile and run samples/net/sockets/echo:
 *     # cmake -DBOARD=qemu_x86 \
 *       -DOVERLAY_CONFIG="overlay-tcp2.conf;overlay-tcp2-slip.conf" ..
 * 3. Compile and run the sanity check:
 *     https://github.com/intel/net-test-suites
 *     # ttcn3_start test_suite tcp2_check_3_runs.cfg
 *
 * NOTE: All modifications should pass the sanity check.
 *
 * To run with E1000 ethernet driver and to be able to smoke
 * test the connectivity from the host:
 *
 * 1. Get Zephyrproject's net-tools and create a pseudo interface:
 *     https://github.com/zephyrproject-rtos/net-tools
 *     # sudo ./net-setup.sh --config zeth.conf
 * 2. Compile and run samples/net/sockets/echo:
 *     # cmake -DBOARD=qemu_x86 \
 *       -DOVERLAY_CONFIG="overlay-tcp2.conf;overlay-tcp2-eth.conf" ..
 * 3. Connect with telnet:
 *     # telnet 192.0.2.1 4242
 */

#define LOG_LEVEL 4
#include <logging/log.h>
LOG_MODULE_REGISTER(net_tcp2);

#include <stdio.h>
#include <stdlib.h>
#include <zephyr.h>
#include <json.h>
#include <net/net_pkt.h>
#include "tp.h"

#define is(_a, _b) (strcmp((_a), (_b)) == 0)

#define tcp_dbg(fmt, args...) printk("%s: " fmt "\n", __func__, ## args)
#define tcp_err(fmt, args...) do {			\
	LOG_ERR("Error: " fmt, ## args);		\
	k_oops();					\
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
#define th_get(_x) ((struct tcphdr *) (ip_get(_x) + 1))

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
	TH_NONE = 0,
	TH_FIN = 1,
	TH_SYN = 1 << 1,
	TH_RST = 1 << 2,
	TH_PSH = 1 << 3,
	TH_ACK = 1 << 4,
	TH_URG = 1 << 5,
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
	sys_slist_t nbufs;
};

struct tcp { /* TCP connection */
	sys_snode_t next;
	enum tcp_state state;
	enum tcp_conn_kind kind;
	int fd;
	u32_t seq;
	u32_t ack;
	struct sockaddr *src;
	struct sockaddr *dst;
	u16_t sport;
	u16_t dport;
	u16_t win;
	struct tcp_win *rcv;
	struct tcp_win *snd;
	sys_slist_t retr;
	struct k_timer timer;
	struct net_if *iface;
};

enum tp_type { /* Test protocol message type */
	TP_NONE = 0,
	TP_COMMAND,
	TP_CONFIG_REQUEST,
	TP_CONFIG_REPLY,
	TP_INTROSPECT_REQUEST,
	TP_INTROSPECT_REPLY,
	TP_INTROSPECT_MEMORY_REQUEST,
	TP_INTROSPECT_MEMORY_REPLY,
	TP_INTROSPECT_PACKETS_REQUEST,
	TP_INTROSPECT_PACKETS_REPLY,
	TP_DEBUG_STOP,
	TP_DEBUG_STEP,
	TP_DEBUG_CONTINUE,
	TP_DEBUG_RESPONSE,
	TP_DEBUG_BREAKPOINT_ADD,
	TP_DEBUG_BREAKPOINT_DELETE,
	TP_TRACE_ADD,
	TP_TRACE_DELETE
};

struct tp {
	enum tp_type type;
	const char *msg;
	const char *status;
	const char *state;
	int seq;
	int ack;
	const char *rcv;
	const char *data;
	const char *op;
};

static sys_slist_t tcp_conns = SYS_SLIST_STATIC_INIT(&tcp_conns);

static bool tp_enabled = IS_ENABLED(CONFIG_NET_TP);
static enum tp_type tp_state;
static sys_slist_t tp_mem = SYS_SLIST_STATIC_INIT(&tp_mem);
static sys_slist_t tp_nbufs = SYS_SLIST_STATIC_INIT(&tp_nbufs);
static sys_slist_t tp_npkts = SYS_SLIST_STATIC_INIT(&tp_npkts);
static sys_slist_t tp_q = SYS_SLIST_STATIC_INIT(&tp_q);

static void tcp_in(struct tcp *conn, struct net_pkt *pkt);
static void tcp_out(struct tcp *conn, u8_t th_flags);
static void tcp_timer_cb(struct k_timer *timer);
static void tcp_timer_cancel(struct tcp *conn);
static struct tcp_win *tcp_win_new(const char *name);
static void tcp_win_free(struct tcp_win *win);
static struct net_pkt *net_pkt_get(size_t len);

ssize_t tcp_recv(int fd, void *buf, size_t len, int flags);
ssize_t tcp_send(int fd, const void *buf, size_t len, int flags);

NET_BUF_POOL_VAR_DEFINE(tcp2_nbufs, 16, 128, NULL);

#define PKT_DST 0
#define PKT_SRC 1

struct tp_mem {
	sys_snode_t next;
	const char *file;
	int line;
	size_t size;
	u8_t mem[];
};

struct tp_nbuf {
	sys_snode_t next;
	struct net_buf *nbuf;
	const char *file;
	int line;
};

struct tp_npkt {
	sys_snode_t next;
	struct net_pkt *pkt;
	const char *file;
	int line;
};

static const char *basename(const char *path)
{
	char *file = (char *) path, *ch = file;

	for (; *ch != '\0'; ch++) {
		if (*ch == '/' || *ch == '\\') {
			file = ch + 1;
		}
	}

	return file;
}

void tp_mstat(void)
{
	struct tp_mem *mem;

	SYS_SLIST_FOR_EACH_CONTAINER(&tp_mem, mem, next) {
		tcp_dbg("len=%zu %s:%d", mem->size,
			basename(mem->file), mem->line);
	}
}

void *tp_malloc(size_t size, char *file, int line)
{
	struct tp_mem *m = k_malloc(sizeof(struct tp_mem) + size);

	m->size = size;
	m->file = basename(file);
	m->line = line;

	sys_slist_append(&tp_mem, (sys_snode_t *) m);

	return &m->mem;
}

void tp_free(void *ptr)
{
	struct tp_mem *m = ptr - sizeof(struct tp_mem);

	if (!sys_slist_find_and_remove(&tp_mem, (sys_snode_t *) m)) {
		tcp_assert(false, "Invalid free()");
	}

	k_free(m);
}

void *tp_calloc(size_t nmemb, size_t size, char *file, int line)
{
	size *= nmemb;

	void *ptr = tp_malloc(size, file, line);

	memset(ptr, 0, size);

	return ptr;
}

#define tcp_malloc(_size) tp_malloc(_size, __FILE__, __LINE__)
#define tcp_calloc(_nmemb, _size) tp_calloc(_nmemb, _size, __FILE__, __LINE__)
#define tcp_free(_ptr) tp_free(_ptr)

static struct net_buf *tp_nbuf_alloc(size_t len, const char *file, int line,
					const char *func)
{
	struct net_buf *nbuf = net_buf_alloc_len(&tcp2_nbufs, len, K_NO_WAIT);
	struct tp_nbuf *tp_nbuf = k_malloc(sizeof(struct tp_nbuf));

	tcp_assert(len, "");
	tcp_assert(nbuf, "Out of nbufs");

	tcp_dbg("size=%d %p %s:%d %s()", nbuf->size, nbuf,
		basename(file), line, func);

	tp_nbuf->nbuf = nbuf;
	tp_nbuf->file = basename(file);
	tp_nbuf->line = line;

	sys_slist_append(&tp_nbufs, (sys_snode_t *) tp_nbuf);

	return nbuf;
}

static void tp_nbuf_unref(struct net_buf *nbuf, const char *file, int line,
				const char *func)
{
	bool found = false;
	struct tp_nbuf *tp_nbuf;

	tcp_dbg("len=%d %p %s:%d %s()", nbuf->len, nbuf,
		basename(file), line, func);

	SYS_SLIST_FOR_EACH_CONTAINER(&tp_nbufs, tp_nbuf, next) {
		if (tp_nbuf->nbuf == nbuf) {
			found = true;
			break;
		}
	}

	tcp_assert(found, "Invalid tp_nbuf_unref(%p): %s:%d", nbuf,
		basename(file), line);

	sys_slist_find_and_remove(&tp_nbufs, (sys_snode_t *) tp_nbuf);

	net_buf_unref(nbuf);

	k_free(tp_nbuf);
}

static void tp_nbstat(void)
{
	struct tp_nbuf *tp_nbuf;

	SYS_SLIST_FOR_EACH_CONTAINER(&tp_nbufs, tp_nbuf, next) {
		tcp_dbg("%s:%d len=%d", tp_nbuf->file, tp_nbuf->line,
			tp_nbuf->nbuf->len);
	}
}

#define tcp_nbuf_alloc(_len) tp_nbuf_alloc(_len, __FILE__, __LINE__, __func__)
#define tcp_nbuf_unref(_nbuf) tp_nbuf_unref(_nbuf, __FILE__, __LINE__, __func__)

void tp_npstat(void)
{
	struct tp_npkt *pkt;

	SYS_SLIST_FOR_EACH_CONTAINER(&tp_npkts, pkt, next) {
		tcp_dbg("%s:%d %p", pkt->file, pkt->line, pkt->pkt);
	}
}

static struct net_pkt *tp_npkt_alloc(size_t len, char *file, int line)
{
	struct net_pkt *pkt = net_pkt_get(len);
	struct tp_npkt *tp_npkt = k_malloc(sizeof(struct tp_npkt));

	tcp_assert(tp_npkt, "");

	tp_npkt->pkt = pkt;
	tp_npkt->file = basename(file);
	tp_npkt->line = line;

	sys_slist_append(&tp_npkts, (sys_snode_t *) tp_npkt);

	return pkt;
}

static struct net_pkt *tp_npkt_clone(struct net_pkt *pkt, char *file, int line)
{
	struct tp_npkt *tp_npkt = k_malloc(sizeof(struct tp_npkt));

	pkt = net_pkt_clone(pkt, K_NO_WAIT);

	tp_npkt->pkt = pkt;
	tp_npkt->file = basename(file);
	tp_npkt->line = line;

	sys_slist_append(&tp_npkts, (sys_snode_t *) tp_npkt);

	return pkt;
}

static void tp_npkt_unref(struct net_pkt *pkt)
{
	bool found = false;
	struct tp_npkt *tp_npkt;

	SYS_SLIST_FOR_EACH_CONTAINER(&tp_npkts, tp_npkt, next) {
		if (tp_npkt->pkt == pkt) {
			found = true;
			break;
		}
	}

	tcp_assert(found, "Invalid tp_npkt_unref()");

	sys_slist_find_and_remove(&tp_npkts, (sys_snode_t *) tp_npkt);

	net_pkt_unref(tp_npkt->pkt);

	k_free(tp_npkt);
}

#if 1
#define tcp_npkt_alloc(_len) tp_npkt_alloc(_len, __FILE__, __LINE__)
#define tcp_npkt_clone(_pkt) tp_npkt_clone(_pkt, __FILE__, __LINE__)
#define tcp_npkt_unref(_pkt) tp_npkt_unref(_pkt)
#endif

#if 0
#define tcp_npkt_alloc(_len) net_pkt_get(_len)
#define tcp_npkt_clone(_pkt) net_pkt_clone(_pkt, K_NO_WAIT)
#define tcp_npkt_unref(_pkt) net_pkt_unref(_pkt)
#endif

static struct sockaddr *sockaddr_new(struct net_pkt *pkt, int which)
{
	struct sockaddr *sa = tcp_malloc(sizeof(struct sockaddr));
	void *addr;
	size_t len;

	sa->sa_family = net_pkt_family(pkt);

	switch (sa->sa_family) {
	case AF_INET: {
		struct net_ipv4_hdr *ip = ip_get(pkt);
		len = sizeof(struct in_addr);
		addr = (which == PKT_SRC) ? &ip->src : &ip->dst;
		break;
	}
	case AF_INET6: default:
		tcp_assert(false, "sa_family %u isn't implemented",
				sa->sa_family);
	}

	memcpy(&sa->data, addr, len);

	return sa;
}

static struct tcp *tcp_conn_new(struct net_pkt *pkt)
{
	struct tcp *conn = tcp_calloc(1, sizeof(struct tcp));
	struct tcphdr *th = th_get(pkt);

	conn->win = 1280;

	conn->src = sockaddr_new(pkt, PKT_DST);
	conn->dst = sockaddr_new(pkt, PKT_SRC);

	conn->sport = ntohs(th->th_dport);
	conn->dport = ntohs(th->th_sport);

	conn->iface = pkt->iface;

	conn->rcv = tcp_win_new("RCV");
	conn->snd = tcp_win_new("SND");

	sys_slist_init(&conn->retr);
	k_timer_init(&conn->timer, tcp_timer_cb, NULL);

	sys_slist_append(&tcp_conns, (sys_snode_t *) conn);
	tcp_in(conn, NULL);

	return conn;
}

static size_t sa_len(int af)
{
	return (af == AF_INET) ? sizeof(struct sockaddr_in) :
		sizeof(struct sockaddr_in6);
}

static int tcp_addr_cmp(struct sockaddr *sa, struct net_pkt *pkt, int which)
{
	struct sockaddr *sa_new = sockaddr_new(pkt, which);
	int ret = 0;

	if (memcmp(sa, sa_new, sa_len(sa->sa_family)) != 0) {
		ret = -1;
	}

	tcp_free(sa_new);

	return ret;
}

static int tcp_conn_cmp(struct tcp *conn, struct net_pkt *pkt)
{
	struct tcphdr *th = th_get(pkt);
	int ret = 0;

	if (conn->sport != ntohs(th->th_dport) ||
			conn->dport != ntohs(th->th_sport) ||
			tcp_addr_cmp(conn->src, pkt, PKT_DST) != 0 ||
			tcp_addr_cmp(conn->dst, pkt, PKT_SRC) != 0) {
		ret = -1;
	}

	return ret;
}

static struct tcp *tcp_conn_search(struct net_pkt *pkt)
{
	bool found = false;
	struct tcp *conn;

	SYS_SLIST_FOR_EACH_CONTAINER(&tcp_conns, conn, next) {
		if (tcp_conn_cmp(conn, pkt) == 0) {
			found = true;
			break;
		}
	}

	return found ? conn : NULL;
}

static void tcp_conn_delete(struct tcp *conn)
{
	tcp_dbg("");

	tcp_assert(sys_slist_is_empty(&conn->retr),
			"Retransmission queue isn't empty");

	tcp_win_free(conn->snd);
	tcp_win_free(conn->rcv);

	tcp_free(conn->src);
	tcp_free(conn->dst);

	sys_slist_find_and_remove(&tcp_conns, (sys_snode_t *) conn);
	memset(conn, 0, sizeof(*conn));
	tcp_free(conn);
	tp_state = TP_NONE;
}

static const char *tcp_state_to_str(enum tcp_state state, bool prefix)
{
	const char *s = NULL;
#define _(_x) case _x: do { s = #_x; goto out; } while (0)
	switch (state) {
	_(TCP_NONE);
	_(TCP_LISTEN);
	_(TCP_SYN_SENT);
	_(TCP_SYN_RECEIVED);
	_(TCP_ESTABLISHED);
	_(TCP_FIN_WAIT1);
	_(TCP_FIN_WAIT2);
	_(TCP_CLOSE_WAIT);
	_(TCP_CLOSING);
	_(TCP_LAST_ACK);
	_(TCP_TIME_WAIT);
	_(TCP_CLOSED);
	}
#undef _
	tcp_assert(s, "Invalid TCP state: %u", state);
out:
	return prefix ? s : (s + 4);
}

static const char *tcp_th(struct tcp *conn, struct net_pkt *pkt)
{
#define FL_MAX 80
	static char buf[FL_MAX];
	char *s = buf;
	struct tcphdr *th = th_get(pkt);
	struct net_ipv4_hdr *ip = ip_get(pkt);
	u8_t fl = th->th_flags;
	ssize_t data_len = ntohs(ip->len) - sizeof(*ip) - th->th_off * 4;

	*s = '\0';

	if (fl) {
		if (fl & TH_SYN) {
			s += sprintf(s, "SYN=%u,", th_seq(th));
		}
		if (fl & TH_FIN) {
			s += sprintf(s, "FIN=%u,", th_seq(th));
		}
		if (fl & TH_ACK) {
			s += sprintf(s, "ACK=%u,", th_ack(th));
		}
		if (fl & TH_PSH) {
			strcat(s, "PSH,");
			s += 4;
		}
		if (fl & TH_RST) {
			strcat(s, "RST,");
			s += 4;
		}
		if (fl & TH_URG) {
			strcat(s, "URG,");
			s += 4;
		}
		s[strlen(s) - 1] = '\0';
		s--;
	}

	if (data_len > 0) {
		sprintf(s, ", len=%ld", data_len);
	}

	return buf;
}

static struct tcp_win *tcp_win_new(const char *name)
{
	struct tcp_win *win = tcp_calloc(1, sizeof(struct tcp_win));

	win->name = tcp_malloc(strlen(name) + 1);

	strcpy(win->name, name);

	sys_slist_init(&win->nbufs);

	return win;
}

static void tcp_win_free(struct tcp_win *win)
{
	struct net_buf *nbuf;

	SYS_SLIST_FOR_EACH_CONTAINER(&win->nbufs, nbuf, next) {
		tcp_dbg("%s %p len=%d", win->name, nbuf, nbuf->len);
		tcp_nbuf_unref(nbuf);
	}

	tcp_free(win->name);
	tcp_free(win);
}

static void tcp_win_push(struct tcp_win *win, const void *buf, size_t len)
{
	struct net_buf *nbuf = tcp_nbuf_alloc(len);
	size_t prev_len = win->len;

	tcp_assert(len, "");

	memcpy(net_buf_add(nbuf, len), buf, len);

	sys_slist_append(&win->nbufs, &nbuf->next);

	win->len += len;

	tcp_dbg("%s %p %zu->%zu byte(s)", win->name, nbuf, prev_len, win->len);
}

static struct net_buf *tcp_win_pop(struct tcp_win *win, size_t len)
{
	struct net_buf *nbuf = (void *) sys_slist_get(&win->nbufs);
	size_t prev_len = win->len;

	tcp_assert(nbuf, "%s window is empty", win->name);

	nbuf = CONTAINER_OF(nbuf, struct net_buf, next);

	win->len -= nbuf->len;

	tcp_dbg("%s %p %zu->%zu byte(s)", win->name, nbuf, prev_len, win->len);

	return nbuf;
}

/* TCP state machine, everything happens here */
static void tcp_in(struct tcp *conn, struct net_pkt *pkt)
{
	enum tcp_state next = TCP_NONE;
	struct tcphdr *th = pkt ? th_get(pkt) : NULL;

	tcp_dbg("%s %s %u/%u", (pkt && net_pkt_get_len(pkt) >=
		(sizeof(struct net_ipv4_hdr) + sizeof(struct tcphdr))) ?
		tcp_th(conn, pkt) : "",
		conn->state != TCP_NONE ? tcp_state_to_str(conn->state, false) :
		"", conn->seq, conn->ack);
next_state:
	switch (conn->state) {
	case TCP_NONE:
		next = TCP_LISTEN;
		break;
	case TCP_LISTEN:
		/* TODO: next 4 lines into one op */
		if (conn->kind == TCP_ACTIVE) {
			tcp_out(conn, TH_SYN);
			conn->seq++;
			next = TCP_SYN_SENT;
		}
		if (th && th->th_flags == TH_SYN) {
			conn->ack = th_seq(th);
			next = TCP_SYN_RECEIVED;
		}
		break;
	case TCP_SYN_RECEIVED:
		conn->ack++;
		tcp_out(conn, TH_SYN | TH_ACK);
		conn->seq++;
		next = TCP_SYN_SENT;
		break;
	case TCP_SYN_SENT:
		/* TODO: validate/store sn in one op */
		/* TODO: get to LISTENING after timeout; reset ack on SYN? */
		/* passive open */
		if (th && th->th_flags == TH_ACK && th_seq(th) == conn->ack) {
			tcp_timer_cancel(conn);
			next = TCP_ESTABLISHED;
		}
		if (th && th->th_flags == (TH_SYN | TH_ACK) &&
				th_ack(th) == conn->seq) { /* active open */
			tcp_timer_cancel(conn);
			conn->ack = th_seq(th) + 1;
			tcp_out(conn, TH_ACK);
			next = TCP_ESTABLISHED;
		}
		break;
	case TCP_ESTABLISHED:
		if (th && th->th_flags & TH_RST) {
			next = TCP_CLOSED;
			break;
		}
		if (!th && !sys_slist_is_empty(&conn->snd->nbufs)) {
			size_t data_len = conn->snd->len;
			tcp_out(conn, TH_PSH);
			conn->seq += data_len;
		}
		if (th && th->th_flags == (TH_ACK | TH_FIN)
				&& th_seq(th) == conn->ack) { /* full-close */
			conn->ack++;
			tcp_out(conn, TH_ACK);
			next = TCP_CLOSE_WAIT;
			break;
		}
		/* Non piggybacking version for clarity now */
		if (th && th->th_flags & TH_PSH && th_seq(th) == conn->ack) {
			/* TODO: next 4 lines into one op */
			struct net_ipv4_hdr *ip = ip_get(pkt);
			size_t th_off = th->th_off * 4;
			size_t data_len = ntohs(ip->len) - sizeof(*ip) - th_off;
			void *data = th_get(pkt) + th_off;

			tcp_win_push(conn->rcv, data, data_len);
			tcp_win_push(conn->snd, data, data_len);

			conn->ack += data_len;
			tcp_out(conn, TH_ACK); /* ack the data */

			data_len = conn->snd->len; /* XXX */
			tcp_out(conn, TH_PSH); /* echo the input */
			conn->seq += data_len;
		}
		if (th && th->th_flags == TH_ACK && th_seq(th) == conn->ack) {
			//tcp_win_clear(&conn->snd);
			break;
		}
		break; /* TODO: Catch all the rest here */
	case TCP_CLOSE_WAIT:
		tcp_out(conn, TH_FIN | TH_ACK);
		next = TCP_LAST_ACK;
		break;
	case TCP_LAST_ACK:
		if (th && th->th_flags & TH_RST) {
			next = TCP_CLOSED;
		}
		if (th && th->th_flags & TH_ACK && th_seq(th) == conn->ack) {
			next = TCP_CLOSED;
		}
		break;
	case TCP_CLOSED:
		if (tp_enabled == false) {
			tcp_conn_delete(conn);
		}
		break;
	case TCP_TIME_WAIT:
	case TCP_CLOSING:
	case TCP_FIN_WAIT1:
	case TCP_FIN_WAIT2:
	default:
		tcp_assert(false, "%s is unimplemented",
				tcp_state_to_str(conn->state, true));
	}

	if (next) {
		th = NULL;
		tcp_dbg("%s->%s", tcp_state_to_str(conn->state, false),
			tcp_state_to_str(next, false));
		conn->state = next;
		next = TCP_NONE;
		goto next_state;
	}
}

static struct net_pkt *net_pkt_get(size_t len)
{
	struct net_pkt *pkt = net_pkt_get_reserve_tx(K_NO_WAIT);
	struct net_buf *nbuf = net_pkt_get_frag(pkt, K_NO_WAIT);

	tcp_assert(pkt && nbuf, "");

	pkt->family = AF_INET;

	net_buf_add(nbuf, len);
	net_pkt_frag_insert(pkt, nbuf);

	return pkt;
}

static void net_pkt_adj(struct net_pkt *pkt, int req_len)
{
	struct net_ipv4_hdr *ip = ip_get(pkt);
	u16_t len = ntohs(ip->len) + req_len;

	ip->len = htons(len);

	if (ip->proto == IPPROTO_UDP) {
		struct net_udp_hdr *uh = (void *) (ip + 1);
		len = ntohs(uh->len) + req_len;
		uh->len = htons(len);
	}
}

static const char *hex_to_str(void *data, size_t len)
{
	static char s[512];
	size_t i, j;

	for (i = 0, j = 0; i < len; i++, j += 3) {
		sprintf(&s[j], "%02x ", *((u8_t *) data + i));
	}

	return s;
}

static enum tp_type tp_msg_to_type(const char *s)
{
	enum tp_type type = TP_NONE;

#define is_tp(_s, _type) do {		\
	if (is(#_type, _s)) {		\
		type = _type;		\
		goto out;		\
	}				\
} while (0)

	is_tp(s, TP_COMMAND);
	is_tp(s, TP_INTROSPECT_REQUEST);
	is_tp(s, TP_DEBUG_STOP);
	is_tp(s, TP_DEBUG_STEP);
	is_tp(s, TP_DEBUG_CONTINUE);
#undef is_tp
out:
	tcp_assert(type != TP_NONE, "Invalid message: %s", s);
	return type;
}

static struct net_pkt *tp_make(void)
{
	struct net_pkt *pkt = tcp_npkt_alloc(sizeof(struct net_ipv4_hdr) +
					sizeof(struct net_udp_hdr));
	struct net_ipv4_hdr *ip = (void *) net_pkt_ip_data(pkt);
	struct net_udp_hdr *uh = (void *) (ip + 1);
	size_t len = sizeof(*ip) + sizeof(*uh);

	memset(ip, 0, len);

	ip->vhl = 0x45;
	ip->ttl = 64;
	ip->proto = IPPROTO_UDP;
	ip->len = htons(len);
	net_addr_pton(AF_INET, CONFIG_NET_CONFIG_MY_IPV4_ADDR, &ip->src);
	net_addr_pton(AF_INET, CONFIG_NET_CONFIG_PEER_IPV4_ADDR, &ip->dst);

	uh->src_port = htons(4242);
	uh->dst_port = htons(4242);
	uh->len = htons(sizeof(*uh));

	return pkt;
}

static void net_pkt_send(struct net_pkt *pkt)
{
	net_pkt_ref(pkt);

	if (net_send_data(pkt) < 0) {
		tcp_err("net_send_data()");
		tcp_npkt_unref(pkt);
	}

	tcp_npkt_unref(pkt);
}

static void tp_output(struct net_if *iface, void *data, size_t data_len)
{
	struct net_pkt *pkt = tp_make();

	net_pkt_append(pkt, data_len, data, K_NO_WAIT);

	net_pkt_adj(pkt, data_len);

	pkt->iface = iface;

	net_pkt_send(pkt);
}

static void tcp_step(void)
{
	struct net_pkt *pkt = (void *) sys_slist_get(&tp_q);
	struct tcp *conn;

	if (pkt) {
		conn = tcp_conn_search(pkt);

		if (conn == NULL) {
			conn = tcp_conn_new(pkt);
		}

		tcp_in(conn, pkt);
	}
}

static size_t str_to_hex(void *buf, size_t bufsize, const char *s)
{
	size_t i, j, len = strlen(s);

	tcp_assert((len % 2) == 0, "Invalid string: %s", s);

	for (i = 0, j = 0; i < len; i += 2, j++) {

		u8_t byte = (s[i] - '0') << 4 | (s[i + 1] - '0');

		((u8_t *) buf)[j] = byte;
	}

	return j;
}

#define json_str(_type, _field) \
	JSON_OBJ_DESCR_PRIM(struct _type, _field, JSON_TOK_STRING)
#define json_num(_type, _field) \
	JSON_OBJ_DESCR_PRIM(struct _type, _field, JSON_TOK_NUMBER)

static const struct json_obj_descr tp_descr[] = {
	json_str(tp, msg),
	json_str(tp, status),
	json_str(tp, state),
	json_num(tp, seq),
	json_num(tp, ack),
	json_str(tp, rcv),
	json_str(tp, data),
	json_str(tp, op),
};

static void tcp_to_json(struct tcp *conn, void *data, size_t *data_len)
{
	int error;
	struct tp tp = {
		.msg = "",
		.status = "",
		.state = tcp_state_to_str(conn->state, true),
		.seq = conn->seq,
		.ack = conn->ack,
		.rcv = "",
		.data = "",
		.op = "",
	};

	if (conn->rcv->len) {
		static char buf[128];
		ssize_t len;
		struct net_buf *nbuf = tcp_win_pop(conn->rcv, 1);

		len = net_buf_linearize(buf, sizeof(buf), nbuf, 0, nbuf->len);

		tcp_nbuf_unref(nbuf);

		tp.data = hex_to_str(buf, len);
		tcp_dbg("data=%s", tp.data);
	}

	error = json_obj_encode_buf(tp_descr, ARRAY_SIZE(tp_descr), &tp,
					data, *data_len);
	if (error) {
		tcp_err("json_obj_encode_buf()");
	}

	*data_len = error ? 0 : strlen(data);
}

static struct tp *json_to_tp(void *data, size_t data_len)
{
	static struct tp tp;

	memset(&tp, 0, sizeof(tp));

	if (json_obj_parse(data, data_len, tp_descr, ARRAY_SIZE(tp_descr),
			&tp) < 0) {
		tcp_err("json_obj_parse()");
	}

	tp.type = tp_msg_to_type(tp.msg);

	return &tp;
}

#if defined CONFIG_NET_TP
/* Test protolol input */
void tp_input(struct net_pkt *pkt)
{
	struct net_ipv4_hdr *ip = (void *) net_pkt_ip_data(pkt);
	struct net_udp_hdr *uh = (void *) (ip + 1);
	size_t data_len = ntohs(uh->len) - sizeof(*uh);
	struct tcp *conn = tcp_conn_search(pkt);
	size_t json_len = 0;
	struct tp *tp;
	static char buf[512];

	net_pkt_skip(pkt, sizeof(*ip) + sizeof(*uh));
	net_pkt_read_new(pkt, buf, data_len);
	buf[data_len] = '\0';
	data_len += 1;

	tp = json_to_tp(buf, data_len);

	switch (tp->type) {
	case TP_COMMAND:
		if (is("CONNECT", tp->op)) {
			u8_t data_to_send[128];
			size_t len = str_to_hex(data_to_send,
						sizeof(data_to_send), tp->data);
			conn = tcp_conn_new(pkt);
			conn->kind = TCP_ACTIVE;
			if (len > 0) {
				tcp_win_push(conn->snd, data_to_send, len);
			}
			tcp_in(conn, NULL);
		}
		if (is("CLOSE", tp->op)) {
			tcp_conn_delete(tcp_conn_search(pkt));
			tp_mstat();
			tp_nbstat();
			tp_npstat();
		}
		if (is("RECV", tp->op)) {
			tcp_dbg("rcv=%zd", tcp_recv(0, NULL, 0, 0));
		}
		break;
	case TP_INTROSPECT_REQUEST:
		json_len = sizeof(buf);
		tcp_to_json(conn, buf, &json_len);
		break;
	case TP_DEBUG_STOP: case TP_DEBUG_CONTINUE:
		tp_state = tp->type;
		break;
	case TP_DEBUG_STEP:
		tcp_step();
		break;
	default:
		tcp_assert(false, "Unimplemented tp command: %s", tp->msg);
	}

	if (json_len) {
		tp_output(pkt->iface, buf, json_len);
	}
}
#else
void tp_input(struct net_pkt *pkt) { return; }
#endif

static struct net_pkt *tcp_make(struct tcp *conn, u8_t th_flags)
{
	struct net_pkt *pkt = tcp_npkt_alloc(sizeof(struct net_ipv4_hdr) +
						sizeof(struct tcphdr));
	struct net_ipv4_hdr *ip = (void *) net_pkt_ip_data(pkt);
	struct tcphdr *th = (void *) (ip + 1);
	size_t len = sizeof(*ip) + sizeof(*th);

	memset(ip, 0, len);

	ip->vhl = 0x45;
	ip->ttl = 64;
	ip->proto = IPPROTO_TCP;
	ip->len = htons(len);
	net_addr_pton(AF_INET, CONFIG_NET_CONFIG_MY_IPV4_ADDR, &ip->src);
	net_addr_pton(AF_INET, CONFIG_NET_CONFIG_PEER_IPV4_ADDR, &ip->dst);

	th->th_off = 5;
	th->th_flags = th_flags;
	th->th_win = htons(conn->win);
	th->th_sport = htons(conn->sport);
	th->th_dport = htons(conn->dport);
	th->th_seq = htonl(conn->seq);

	if (th_flags & TH_ACK) {
		th->th_ack = htonl(conn->ack);
	}

	pkt->iface = conn->iface;

	return pkt;
}

static u32_t _cs(void *data, size_t len)
{
	u32_t s = 0;

	for ( ; len > 1; len -= 2, data = (u8_t *) data + 2)
		s += *((u16_t *) data);

	if (len)
		s += *((u8_t *) data);

	return s;
}

static uint16_t cs(int32_t s)
{
	return ~((s & 0xFFFF) + (s >> 16));
}

static void tcp_csum(struct net_pkt *pkt)
{
	struct net_ipv4_hdr *ip = (void *) net_pkt_ip_data(pkt);
	struct tcphdr *th = (void *) (ip + 1);
	u16_t len = ntohs(ip->len) - 20;
	u32_t s;

	ip->chksum = cs(_cs(ip, sizeof(*ip)));

	s = _cs(&ip->src, sizeof(struct in_addr) * 2);
	s += ntohs(ip->proto + len);

	th->th_sum = 0;
	s += _cs(th, len);

	th->th_sum = cs(s);
}

static void tcp_timer_cb(struct k_timer *timer)
{
	struct tcp *conn = k_timer_user_data_get(timer);
	struct net_pkt *pkt = (void *) sys_slist_peek_head(&conn->retr);

	pkt = CONTAINER_OF(pkt, struct net_pkt, next);

	tcp_assert(pkt, "No packet in the retransmission queue");

	pkt = tcp_npkt_clone(pkt);

	tcp_dbg("%s", pkt ? tcp_th(conn, pkt) : "");

	net_pkt_send(pkt);

	k_timer_user_data_set(&conn->timer, conn);
	k_timer_start(&conn->timer, K_MSEC(50), 0);
}

static void tcp_timer_cancel(struct tcp *conn)
{
	struct net_pkt *pkt = (void *) sys_slist_get(&conn->retr);

	k_timer_stop(&conn->timer);

	tcp_assert(pkt, "No packet in the retransmission queue");

	pkt = CONTAINER_OF(pkt, struct net_pkt, next);

	tcp_dbg("%s", pkt ? tcp_th(conn, pkt) : "");

	tcp_npkt_unref(pkt);
}

static void tcp_timer_subscribe(struct tcp *conn, struct net_pkt *pkt)
{
	pkt = tcp_npkt_clone(pkt);

	tcp_dbg("%s", tcp_th(conn, pkt));

	sys_slist_append(&conn->retr, &pkt->next);

	k_timer_user_data_set(&conn->timer, conn);

	k_timer_start(&conn->timer, K_MSEC(500), 0);
}

static void tcp_out(struct tcp *conn, u8_t th_flags)
{
	struct net_pkt *pkt = tcp_make(conn, th_flags);

	if (th_flags & TH_PSH) {

		struct net_buf *data = tcp_win_pop(conn->snd, 1);

		/* TODO: There's a checksum problem with the following */
		/*net_pkt_frag_add(pkt, data);*/

		net_pkt_append(pkt, data->len, data->data, K_NO_WAIT);

		net_pkt_adj(pkt, data->len);

		tcp_nbuf_unref(data);
	}

	tcp_csum(pkt);

	if (th_flags & TH_SYN) {
		tcp_timer_subscribe(conn, pkt);
	}

	tcp_dbg("%s", tcp_th(conn, pkt));

	net_pkt_send(pkt);
}

static bool tp_tap_input(struct net_pkt *pkt)
{
	bool tap = tp_state != TP_NONE;

	if (tap) {
		net_pkt_ref(pkt);
		/* STAILQ_INSERT_HEAD(&tp_q, pkt, stq_next); */
	}

	return tap;
}

void tcp_input(struct net_pkt *pkt)
{
	struct tcp *conn;
	struct tcphdr *th = (pkt && net_pkt_get_len(pkt) >=
		(sizeof(struct net_ipv4_hdr) + sizeof(struct tcphdr))) ?
		th_get(pkt) : NULL;

	if (tp_tap_input(pkt)) {
		goto out;
	}

	if (th == NULL) {
		goto out;
	}

	conn = tcp_conn_search(pkt);
	if (conn == NULL && th->th_flags == TH_SYN) {
		conn = tcp_conn_new(pkt);
	}

	if (conn) {
		tcp_in(conn, pkt);
	}
out:
	return;
}

ssize_t tcp_recv(int fd, void *buf, size_t len, int flags)
{
	struct tcp *conn = tcp_conn_search(NULL);

	return conn->rcv->len;
}

ssize_t tcp_send(int fd, const void *buf, size_t len, int flags)
{
	return 0;
}

void tcp_bind(void) { }
void tcp_listen(void) { }
void tcp_connect(void) { }
void tcp_accept(void) { }
void tcp_close(void) { }
