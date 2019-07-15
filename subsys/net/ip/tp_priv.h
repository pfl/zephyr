/*
 * Copyright (c) 2018-2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef TP_PRIV_H
#define TP_PRIV_H

#ifdef __cplusplus
extern "C" {
#endif

#include <zephyr.h>

#define tp_dbg(fmt, args...) printk("%s: " fmt "\n", __func__, ## args)
#define tp_err(fmt, args...) do {				\
	printk("%s: Error: " fmt "\n", __func__, ## args);	\
	k_oops();						\
} while (0)

#define tp_assert(cond, fmt, args...) do {			\
	if ((cond) == false) {					\
		printk("%s: Assertion failed: %s, " fmt "\n",	\
			__func__, #cond, ## args);		\
		k_oops();					\
	}							\
} while (0)

struct tp_mem {
	sys_snode_t next;
	const char *file;
	int line;
	size_t size;
	u8_t mem[];
};

#ifdef __cplusplus
}
#endif

#endif /* TP_PRIV_H */
