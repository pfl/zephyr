/*
 * Copyright (c) 2018-2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef TCP2_H
#define TCP2_H

#ifdef __cplusplus
extern "C" {
#endif

void tcp_input(struct net_pkt *pkt);
void tp_input(struct net_pkt *pkt);

#ifdef __cplusplus
}
#endif

#endif /* TCP2_H */
