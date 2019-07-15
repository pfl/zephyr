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

#include <net/net_pkt.h>

void tp_input(struct net_pkt *pkt);

#ifdef __cplusplus
}
#endif

#endif /* TP_H */
