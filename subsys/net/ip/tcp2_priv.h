/*
 * Copyright (c) 2018-2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "tp.h"

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

#define tcp_malloc(_size) tp_malloc(_size, basename(__FILE__), __LINE__)
#define tcp_calloc(_nmemb, _size) \
	tp_calloc(_nmemb, _size, basename(__FILE__), __LINE__)
#define tcp_free(_ptr) tp_free(_ptr, basename(__FILE__), __LINE__, __func__)

#define PKT_DST 0
#define PKT_SRC 1

#define tcp_nbuf_alloc(_len) \
	tp_nbuf_alloc(_len, basename(__FILE__), __LINE__, __func__)
#define tcp_nbuf_unref(_nbuf) \
	tp_nbuf_unref(_nbuf, basename(__FILE__), __LINE__, __func__)

#define tcp_pkt_alloc(_len) tp_pkt_alloc(_len, basename(__FILE__), __LINE__)
#define tcp_pkt_clone(_pkt) tp_pkt_clone(_pkt, basename(__FILE__), __LINE__)
#define tcp_pkt_unref(_pkt) tp_pkt_unref(_pkt, basename(__FILE__), __LINE__)

#define TP_SEQ 0
#define TP_ACK 1

#define conn_seq(_conn, _req) \
	tp_seq_track(TP_SEQ, &(_conn)->seq, (_req), basename(__FILE__), \
			__LINE__, __func__)
#define conn_ack(_conn, _req) \
	tp_seq_track(TP_ACK, &(_conn)->ack, (_req), basename(__FILE__), \
			__LINE__, __func__)
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

#define FIN TH_FIN /* drop the prefix in the above enum? */
#define SYN TH_SYN
#define RST TH_RST
#define PSH TH_PSH
#define ACK TH_ACK
#define URG TH_URG

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
	int retries; /* number of retransmissions */
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

struct tp_seq {
	sys_snode_t next;
	const char *file;
	int line;
	const char *func;
	int kind;
	int req;
	u32_t value;
	u32_t old_value;
	int of;
};

struct tp_nbuf {
	sys_snode_t next;
	struct net_buf *nbuf;
	const char *file;
	int line;
};

struct tp_pkt {
	sys_snode_t next;
	struct net_pkt *pkt;
	const char *file;
	int line;
};

