/*
 * Copyright (c) 2018-2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef TP_H
#define TP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <net/net_pkt.h>

void tp_input(struct net_pkt *pkt);

void *tp_malloc(size_t size, const char *file, int line);
void tp_free(void *ptr, const char *file, int line, const char *func);
void *tp_calloc(size_t nmemb, size_t size, const char *file, int line);
void tp_mem_stat(void);

#ifdef __cplusplus
}
#endif

#endif /* TP_H */
