/*
 * Copyright (c) 2018-2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Manual:	https://github.com/ozhuraki/zephyr/blob/tcp2-dev/README.md
 * TODO:	https://github.com/ozhuraki/zephyr/blob/tcp2-dev/TODO
 * PR:		https://github.com/zephyrproject-rtos/zephyr/pull/11443/
 */

#define LOG_LEVEL 4
#include <logging/log.h>
LOG_MODULE_REGISTER(net_tcp2);

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <zephyr.h>
#include <net/net_pkt.h>
#include "tcp2.h"
#include "tcp2_priv.h"

static int tcp_rto = 500; /* Retransmission timeout, msec */
static int tcp_retries = 3;
static int tcp_window = 1280; /* Receive window size */
static sys_slist_t tcp_conns = SYS_SLIST_STATIC_INIT(&tcp_conns);

NET_BUF_POOL_DEFINE(tcp2_nbufs, 64/*count*/, 128/*size*/, 0, NULL);

static void tcp_in(struct tcp *conn, struct net_pkt *pkt);
static void tcp_out(struct tcp *conn, u8_t th_flags, ...);
static void tcp_conn_delete(struct tcp *conn);
static void tcp_add_to_retransmit(struct tcp *conn, struct net_pkt *pkt);
static void tcp_retransmit(struct k_timer *timer);
static void tcp_timer_cancel(struct tcp *conn);
static struct tcp_win *tcp_win_new(const char *name);
static void tcp_win_free(struct tcp_win *win);

ssize_t tcp_recv(int fd, void *buf, size_t len, int flags);
ssize_t tcp_send(int fd, const void *buf, size_t len, int flags);

static struct sockaddr *sockaddr_new(struct net_pkt *pkt, int which)
{
	struct sockaddr *sa = tcp_calloc(1, sizeof(struct sockaddr));

	sa->sa_family = net_pkt_family(pkt);

	switch (sa->sa_family) {
	case AF_INET: {
		struct sockaddr_in *sin = (struct sockaddr_in *) sa;
		struct net_ipv4_hdr *ip = ip_get(pkt);
		struct tcphdr *th = th_get(pkt);

		sin->sin_port = (PKT_SRC == which) ?
					th-> th_sport :th-> th_dport;
		memcpy(&sin->sin_addr,
			(PKT_SRC == which) ? &ip->src : &ip->dst,
			sizeof(sin->sin_addr));
		break;
	}
	case AF_INET6: default:
		tcp_assert(false, "sa_family %u isn't supported yet",
				sa->sa_family);
	}

	return sa;
}

static struct tcp *tcp_conn_new(struct net_pkt *pkt)
{
	struct tcp *conn = tcp_calloc(1, sizeof(struct tcp));
	struct tcphdr *th = th_get(pkt);

	conn->win = tcp_window;

	conn->src = sockaddr_new(pkt, PKT_DST);
	conn->dst = sockaddr_new(pkt, PKT_SRC);

	conn->sport = ntohs(th->th_dport);
	conn->dport = ntohs(th->th_sport);

	conn->iface = pkt->iface;

	conn->rcv = tcp_win_new("RCV");
	conn->snd = tcp_win_new("SND");

	conn->retries = tcp_retries;
	sys_slist_init(&conn->retr);
	k_timer_init(&conn->timer, tcp_retransmit, NULL);

	sys_slist_append(&tcp_conns, (sys_snode_t *) conn);
	tcp_in(conn, NULL);

	return conn;
}

static size_t sa_len(int af)
{
	return (af == AF_INET) ? sizeof(struct sockaddr_in) :
		sizeof(struct sockaddr_in6);
}

static bool tcp_addr_cmp(struct sockaddr *sa, struct net_pkt *pkt, int which)
{
	struct sockaddr *sa_new = sockaddr_new(pkt, which);
	bool is_equal = memcmp(sa, sa_new, sa_len(sa->sa_family)) ?
		false : true;

	tcp_free(sa_new);

	return is_equal;
}

static bool tcp_conn_cmp(struct tcp *conn, struct net_pkt *pkt)
{
	return tcp_addr_cmp(conn->src, pkt, PKT_DST) &&
		tcp_addr_cmp(conn->dst, pkt, PKT_SRC);
}

static struct tcp *tcp_conn_search(struct net_pkt *pkt)
{
	bool found = false;
	struct tcp *conn;

	SYS_SLIST_FOR_EACH_CONTAINER(&tcp_conns, conn, next) {

		found = tcp_conn_cmp(conn, pkt);

		if (found) {
			break;
		}
	}

	return found ? conn : NULL;
}

static void tcp_retransmissions_flush(struct tcp *conn)
{
	sys_snode_t *node;

	if (sys_slist_is_empty(&conn->retr) == false) {
		k_timer_stop(&conn->timer);
	}

	while ((node = sys_slist_get(&conn->retr))) {
		tcp_pkt_unref(CONTAINER_OF(node, struct net_pkt, next));
	}
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

static const char *tcp_th_flags(u8_t fl)
{
#define FL_MAX 80
	static char buf[FL_MAX];
	char *s = buf;
	*s = '\0';

	if (fl) {
		if (fl & SYN) {
			strcat(s, "SYN,");
			s += 4;
		}
		if (fl & FIN) {
			strcat(s, "FIN,");
			s += 4;
		}
		if (fl & ACK) {
			strcat(s, "ACK,");
			s += 4;
		}
		if (fl & PSH) {
			strcat(s, "PSH,");
			s += 4;
		}
		if (fl & RST) {
			strcat(s, "RST,");
			s += 4;
		}
		if (fl & URG) {
			strcat(s, "URG,");
			s += 4;
		}
		s[strlen(s) - 1] = '\0';
	}

	return buf;
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
		if (fl & SYN) {
			s += sprintf(s, "SYN=%u,", th_seq(th));
		}
		if (fl & FIN) {
			s += sprintf(s, "FIN=%u,", th_seq(th));
		}
		if (fl & ACK) {
			s += sprintf(s, "ACK=%u,", th_ack(th));
		}
		if (fl & PSH) {
			strcat(s, "PSH,");
			s += 4;
		}
		if (fl & RST) {
			strcat(s, "RST,");
			s += 4;
		}
		if (fl & URG) {
			strcat(s, "URG,");
			s += 4;
		}
		s[strlen(s) - 1] = '\0';
		s--;
	}

	if (data_len > 0) {
		sprintf(s, ", len=%zd", data_len);
	}

	return buf;
}

static struct tcp_win *tcp_win_new(const char *name)
{
	struct tcp_win *w = tcp_calloc(1, sizeof(struct tcp_win));

	w->name = tcp_malloc(strlen(name) + 1);

	strcpy(w->name, name);

	sys_slist_init(&w->bufs);

	return w;
}

static void tcp_win_free(struct tcp_win *w)
{
	struct net_buf *buf;

	SYS_SLIST_FOR_EACH_CONTAINER(&w->bufs, buf, next) {
		tcp_dbg("%s %p len=%d", w->name, buf, buf->len);
		tcp_nbuf_unref(buf);
	}

	tcp_free(w->name);
	tcp_free(w);
}

static void tcp_win_push(struct tcp_win *w, const void *data, size_t len)
{
	struct net_buf *buf = tcp_nbuf_alloc(&tcp2_nbufs, len);
	size_t prev_len = w->len;

	tcp_assert(len, "Zero length data");

	memcpy(net_buf_add(buf, len), data, len);

	sys_slist_append(&w->bufs, &buf->next);

	w->len += len;

	tcp_dbg("%s %p %zu->%zu byte(s)", w->name, buf, prev_len, w->len);
}

static struct net_buf *tcp_win_pop(struct tcp_win *w, size_t len)
{
	struct net_buf *buf, *out = NULL;
	sys_snode_t *node;

	tcp_assert(len <= w->len, "Insufficient window length");

	while (len) {

		node = sys_slist_get(&w->bufs);

		buf = CONTAINER_OF(node, struct net_buf, next);

		w->len -= buf->len;

		out = out ? net_buf_frag_add(out, buf) : buf;

		len -= buf->len;
	}

	tcp_dbg("%s len=%zu", w->name, net_buf_frags_len(out));

	return out;
}

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

static const char *tcp_conn_state(struct tcp *conn, struct net_pkt *pkt)
{
#define MAX_S 64
	static char s[MAX_S];

	snprintf(s, MAX_S, "%s %s %u/%u", (pkt && net_pkt_get_len(pkt) >=
		(sizeof(struct net_ipv4_hdr) + sizeof(struct tcphdr))) ?
		tcp_th(conn, pkt) : "",
		conn->state != TCP_NONE ? tcp_state_to_str(conn->state, false) :
		"", conn->seq, conn->ack);

	return s;
#undef MAX_S
}

static ssize_t tcp_data_get(struct net_pkt *pkt, void **data, ssize_t *data_len)
{
	struct net_ipv4_hdr *ip = ip_get(pkt);
	struct tcphdr *th = th_get(pkt);
	size_t th_off = th->th_off * 4;
	ssize_t len = ntohs(ip->len) - sizeof(*ip) - th_off;
	static u8_t buf[64];/* The absence of _linearize()
				leads to this temp workaround */
	tcp_assert(len <= sizeof(buf), "Insufficient buffer for data");

	net_pkt_skip(pkt, sizeof(*ip) + th_off);
	net_pkt_read(pkt, buf, len);

	*data = buf;
	*data_len = len;

	return len;
}

#define conn_state(_conn, _s) do {				\
	tcp_dbg("%s->%s",					\
		tcp_state_to_str((_conn)->state, false),	\
		tcp_state_to_str((_s), false));			\
	conn->state = _s;					\
} while (0)

/* TCP state machine, everything happens here */
static void tcp_in(struct tcp *conn, struct net_pkt *pkt)
{
	enum tcp_state next = TCP_NONE;
	struct tcphdr *th = th_get(pkt);

	tcp_dbg("%s", tcp_conn_state(conn, pkt));

	if (ON(RST)) {
		next = TCP_CLOSED;
	}
next_state:
	switch (conn->state) {
	case TCP_NONE:
		conn_state(conn, TCP_LISTEN); /* fall-through */
	case TCP_LISTEN:
		if (conn->kind == TCP_ACTIVE) {
			tcp_out(conn, SYN);
			conn_seq(conn, + 1);
			next = TCP_SYN_SENT;
		} else if (EQ(SYN)) {
			conn_ack(conn, th_seq(th) + 1); /* capture peer's isn */
			next = TCP_SYN_RECEIVED;
		}
		break;
	case TCP_SYN_RECEIVED:
		tcp_out(conn, SYN | ACK);
		conn_seq(conn, + 1);
		next = TCP_SYN_SENT;
		break;
	case TCP_SYN_SENT:
		if (EQ(ACK, SEQ(==))) { /* passive open */
			tcp_timer_cancel(conn);
			next = TCP_ESTABLISHED;
		}
		if (EQ(SYN | ACK, SEQ(==))) { /* active open */
			tcp_timer_cancel(conn);
			conn_ack(conn, th_seq(th) + 1);
			tcp_out(conn, ACK);
			next = TCP_ESTABLISHED;
		}
		break;
	case TCP_ESTABLISHED:
		if (!th && conn->snd->len) { /* TODO: Out of the loop */
			ssize_t data_len;
			tcp_out(conn, PSH, &data_len);
			conn_seq(conn, + data_len);
		}
		if (EQ(FIN | ACK, SEQ(==))) { /* full-close */
			conn_ack(conn, + 1);
			tcp_out(conn, ACK);/* TODO: this could be optional */
			next = TCP_CLOSE_WAIT;
			break;
		}
		if (ON(PSH, SEQ(<))) {
			tcp_out(conn, ACK); /* peer has resent */
			break;
		}
		if (ON(PSH, SEQ(>))) {
			tcp_out(conn, RST);
			next = TCP_CLOSED;
			break;
		}
		/* Non piggybacking version for clarity now */
		if (ON(PSH, SEQ(==))) {
			void *data;
			ssize_t data_len;

			if (tcp_data_get(pkt, &data, &data_len) <= 0) {
				next = TCP_CLOSED;/* TODO: Send a reset? */
				break;
			}

			tcp_win_push(conn->rcv, data, data_len);

			conn_ack(conn, + data_len);
			tcp_out(conn, ACK); /* ack the data */

			if (tp_tcp_echo) { /* TODO: Out of switch()? */
				tcp_win_push(conn->snd, data, data_len);
				tcp_out(conn, PSH, &data_len);
				conn_seq(conn, + data_len);
			}
		}
		if (EQ(ACK, SEQ(==))) {
			/* tcp_win_clear(&conn->snd); */
			break;
		}
		break; /* TODO: Catch all the rest here */
	case TCP_CLOSE_WAIT:
		tcp_out(conn, FIN | ACK);
		next = TCP_LAST_ACK;
		break;
	case TCP_LAST_ACK:
		if (EQ(ACK, SEQ(==))) {
			next = TCP_CLOSED;
		}
		break;
	case TCP_CLOSED:
		tcp_conn_delete(conn);
		break;
	case TCP_TIME_WAIT:
	case TCP_CLOSING:
	case TCP_FIN_WAIT1:
	case TCP_FIN_WAIT2:
	default:
		tcp_assert(false, "%s is unimplemented",
				tcp_state_to_str(conn->state, true));
	}

	if (th) {
		tcp_assert(th->th_flags == 0, "Unconsumed flags: %s",
				tcp_th_flags(th->th_flags));
	}

	if (next) {
		th = NULL;
		conn_state(conn, next);
		next = TCP_NONE;
		goto next_state;
	}
}

void tcp_pkt_adj(struct net_pkt *pkt, int req_len)
{
	struct net_ipv4_hdr *ip = ip_get(pkt);
	u16_t len = ntohs(ip->len) + req_len;

	ip->len = htons(len);
}

static void tcp_pkt_send(struct tcp *conn, struct net_pkt *pkt, bool retransmit)
{
	if (retransmit) {
		tcp_assert(conn, "Invalid retransmit request");
		tcp_add_to_retransmit(conn, tcp_pkt_clone(pkt));
	}

	net_pkt_ref(pkt);

	if (net_send_data(pkt) < 0) {
		tcp_err("net_send_data()");
		tcp_pkt_unref(pkt);
	}

	tcp_pkt_unref(pkt);
}

static void tcp_conn_delete(struct tcp *conn)
{
	tcp_dbg("");

	tp_out(conn->iface, "TP_TRACE", "event", "CONN_DELETE");

	if (tp_tcp_conn_delete == false) {
		return;
	}

	tcp_retransmissions_flush(conn);

	tcp_win_free(conn->snd);
	tcp_win_free(conn->rcv);

	tcp_free(conn->src);
	tcp_free(conn->dst);

	sys_slist_find_and_remove(&tcp_conns, (sys_snode_t *) conn);
	tcp_free(conn);
	tp_state = TP_NONE;
}

static struct net_pkt *tcp_make(struct tcp *conn, u8_t th_flags)
{
	struct net_pkt *pkt = tcp_pkt_alloc(sizeof(struct net_ipv4_hdr) +
						sizeof(struct tcphdr));
	struct net_ipv4_hdr *ip = ip_get(pkt);
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

	if (th_flags & ACK) {
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
	struct net_ipv4_hdr *ip = ip_get(pkt);
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

static void tcp_timer_subscribe(struct tcp *conn, struct net_pkt *pkt)
{
	tcp_dbg("%s", tcp_th(conn, pkt));

	k_timer_user_data_set(&conn->timer, conn);

	k_timer_start(&conn->timer, K_MSEC(tcp_rto), 0);
}

static void tcp_retransmit(struct k_timer *timer)
{
	struct tcp *conn = k_timer_user_data_get(timer);
	sys_snode_t *node =  sys_slist_peek_head(&conn->retr);
	struct net_pkt *pkt = node ?
		CONTAINER_OF(node, struct net_pkt, next) : NULL;

	tcp_assert(pkt, "Empty retransmission queue");

	tcp_dbg("%s", tcp_th(conn, pkt));

	if (conn->retries > 0) {
		tcp_pkt_send(conn, tcp_pkt_clone(pkt), false);

		tcp_timer_subscribe(conn, pkt);

		conn->retries--;
	} else {
		tcp_conn_delete(conn);
	}
}

static void tcp_timer_cancel(struct tcp *conn)
{
	struct net_pkt *pkt = (void *) sys_slist_get(&conn->retr);

	k_timer_stop(&conn->timer);

	tcp_assert(pkt, "No packet in the retransmission queue");

	pkt = CONTAINER_OF(pkt, struct net_pkt, next);

	tcp_dbg("%s", pkt ? tcp_th(conn, pkt) : "");

	tcp_pkt_unref(pkt);
}

static void tcp_add_to_retransmit(struct tcp *conn, struct net_pkt *pkt)
{
	bool subscribe = sys_slist_is_empty(&conn->retr);

	tcp_dbg("%s", tcp_th(conn, pkt));

	sys_slist_append(&conn->retr, &pkt->next);

	if (subscribe) {
		conn->retries = tcp_retries;
		tcp_timer_subscribe(conn, pkt);
	}
}

/* TODO: Rework this */
static void tcp_linearize(struct net_pkt *pkt)
{
	struct net_buf *buf, *tmp;
	sys_slist_t bufs;

	sys_slist_init(&bufs);

	while (pkt->frags) {
		struct net_buf *buf = pkt->frags;
		tmp = net_buf_alloc_len(&tcp2_nbufs, buf->len,
					K_NO_WAIT);
		memcpy(net_buf_add(tmp, buf->len), buf->data, buf->len);
		sys_slist_append(&bufs, &tmp->next);
		net_pkt_frag_del(pkt, NULL, pkt->frags);
	}

	buf = net_pkt_get_frag(pkt, K_NO_WAIT);

	while ((tmp = (void *) sys_slist_get(&bufs))) {
		tmp = CONTAINER_OF(tmp, struct net_buf, next);
		memcpy(net_buf_add(buf, tmp->len), tmp->data, tmp->len);
		net_buf_unref(tmp);
	}

	net_pkt_frag_add(pkt, buf);
}

static void tcp_out(struct tcp *conn, u8_t th_flags, ...)
{
	struct net_pkt *pkt = tcp_make(conn, th_flags);

	if (th_flags & PSH) {
		va_list ap;
		ssize_t *data_len;
		struct net_buf *data_out = tcp_win_pop(conn->snd,
							conn->snd->len);
		struct net_buf *buf = data_out, *tmp;
		size_t len = net_buf_frags_len(data_out);

		va_start(ap, th_flags);
		data_len = va_arg(ap, ssize_t *);
		*data_len = len;
		va_end(ap);

		/* TODO: In an absense of consolidating pull/pullup(),
		 * 	 this is really ugly */
		while (buf) {
			struct net_buf *nb = net_pkt_get_frag(pkt, K_NO_WAIT);
			memcpy(net_buf_add(nb, buf->len), buf->data, buf->len);
			net_pkt_frag_add(pkt, nb);
			tmp = buf->frags;
			buf->frags = NULL;
			tcp_nbuf_unref(buf);
			buf = tmp;
		}
		/* TODO: There's a checksum problem with the following */
		/*net_pkt_frag_add(pkt, data);*/
		tcp_pkt_adj(pkt, len);
	}

	tcp_linearize(pkt);

	tcp_csum(pkt);

	tcp_dbg("%s", tcp_th(conn, pkt));

	tcp_pkt_send(conn, pkt, th_flags & SYN);
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
	if (conn == NULL && th->th_flags == SYN) {
		conn = tcp_conn_new(pkt);
	}

	if (conn) {
		tcp_in(conn, pkt);
	}
out:
	return;
}

static void tcp_chain_free(struct net_buf *buf)
{
	struct net_buf *next;

	for ( ; buf; buf = next) {
		next = buf->frags;
		buf->frags = NULL;
		tcp_nbuf_unref(buf);
	}
}

ssize_t tcp_recv(int fd, void *buf, size_t len, int flags)
{
	struct tcp *conn = (void *) sys_slist_peek_head(&tcp_conns);
	ssize_t bytes_received = conn->rcv->len;
	struct net_buf *data = tcp_win_pop(conn->rcv, bytes_received);

	tcp_assert(bytes_received < len, "Unimplemented");

	net_buf_linearize(buf, len, data, 0, net_buf_frags_len(data));

	tcp_chain_free(data);

	return bytes_received;
}

ssize_t tcp_send(int fd, const void *buf, size_t len, int flags)
{
	struct tcp *conn = (void *) sys_slist_peek_head(&tcp_conns);

	tcp_win_push(conn->snd, buf, len);

	tcp_in(conn, NULL);

	return len;
}

void tcp_bind(void) { }
void tcp_listen(void) { }
void tcp_connect(void) { }
void tcp_accept(void) { }
void tcp_close(void) { }

#if IS_ENABLED(CONFIG_NET_TP)
static sys_slist_t tp_q = SYS_SLIST_STATIC_INIT(&tp_q);

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

static void tp_init(struct tcp *conn, struct tp *tp)
{
	struct tp out = {
		.msg = "",
		.status = "",
		.state = tcp_state_to_str(conn->state, true),
		.seq = conn->seq,
		.ack = conn->ack,
		.rcv = "",
		.data = "",
		.op = "",
	};

	*tp = out;
}

static void tcp_to_json(struct tcp *conn, void *data, size_t *data_len)
{
	struct tp tp;

	tp_init(conn, &tp);

	tp_encode(&tp, data, data_len);
}

/* Test protolol input */
void tp_input(struct net_pkt *pkt)
{
	struct net_ipv4_hdr *ip = ip_get(pkt);
	struct net_udp_hdr *uh = (void *) (ip + 1);
	size_t data_len = ntohs(uh->len) - sizeof(*uh);
	struct tcp *conn = tcp_conn_search(pkt);
	size_t json_len = 0;
	struct tp *tp;
	struct tp_new *tp_new;
	enum tp_type type;
	static char buf[512];

	if (4242 != ntohs(uh->dst_port)) {
		return;
	}

	net_pkt_skip(pkt, sizeof(*ip) + sizeof(*uh));
	net_pkt_read(pkt, buf, data_len);
	buf[data_len] = '\0';
	data_len += 1;

	type = json_decode_msg(buf, data_len);

	data_len = ntohs(uh->len) - sizeof(*uh);
	net_pkt_cursor_init(pkt);
	net_pkt_skip(pkt, sizeof(*ip) + sizeof(*uh));
	net_pkt_read(pkt, buf, data_len);
	buf[data_len] = '\0';
	data_len += 1;

	switch (type) {
	case TP_CONFIG_REQUEST:
		tp_new = json_to_tp_new(buf, data_len);
		break;
	default:
		tp = json_to_tp(buf, data_len);
		break;
	}

	switch (type) {
	case TP_COMMAND:
		if (is("CONNECT", tp->op)) {
			u8_t data_to_send[128];
			size_t len = tp_str_to_hex(data_to_send,
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
			tp_mem_stat();
			tp_nbuf_stat();
			tp_pkt_stat();
			tp_seq_stat();
		}
		if (is("RECV", tp->op)) {
			ssize_t len = tcp_recv(0, buf, sizeof(buf), 0);
			tp_init(conn, tp);
			tp->data = tp_hex_to_str(buf, len);
			tcp_dbg("%zd = tcp_recv(\"%s\")", len, tp->data);
			json_len = sizeof(buf);
			tp_encode(tp, buf, &json_len);
		}
		if (is("SEND", tp->op)) {
			ssize_t len = tp_str_to_hex(buf, sizeof(buf), tp->data);
			tcp_dbg("tcp_send(\"%s\")", tp->data);
			tcp_send(0, buf, len, 0);
		}
		break;
	case TP_CONFIG_REQUEST:
		tp_new_find_and_apply(tp_new, "tcp_rto", &tcp_rto, TP_INT);
		tp_new_find_and_apply(tp_new, "tcp_retries", &tcp_retries,
					TP_INT);
		tp_new_find_and_apply(tp_new, "tcp_window", &tcp_window,
					TP_INT);
		tp_new_find_and_apply(tp_new, "tp_trace", &tp_trace, TP_BOOL);
		tp_new_find_and_apply(tp_new, "tcp_echo", &tp_tcp_echo,
					TP_BOOL);
		tp_new_find_and_apply(tp_new, "tp_tcp_conn_delete",
					&tp_tcp_conn_delete, TP_BOOL);

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
#endif /* end of IS_ENABLED(CONFIG_NET_TP) */
