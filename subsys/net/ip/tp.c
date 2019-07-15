/*
 * Copyright (c) 2018-2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include "tp_priv.h"

static sys_slist_t tp_mem = SYS_SLIST_STATIC_INIT(&tp_mem);

void *tp_malloc(size_t size, const char *file, int line)
{
	struct tp_mem *mem = k_malloc(sizeof(struct tp_mem) + size);

	mem->size = size;
	mem->file = file;
	mem->line = line;

	sys_slist_append(&tp_mem, (sys_snode_t *) mem);

	return &mem->mem;
}

void tp_free(void *ptr, const char *file, int line, const char *func)
{
	struct tp_mem *mem = (void *)((u8_t *) ptr - sizeof(struct tp_mem));

	if (!sys_slist_find_and_remove(&tp_mem, (sys_snode_t *) mem)) {
		tp_assert(false, "%s:%d %s() Invalid free(%p)",
				file, line, func, ptr);
	}

	memset(ptr, 0, mem->size);
	k_free(mem);
}

void *tp_calloc(size_t nmemb, size_t size, const char *file, int line)
{
	size *= nmemb;

	void *ptr = tp_malloc(size, file, line);

	memset(ptr, 0, size);

	return ptr;
}

void tp_mem_stat(void)
{
	struct tp_mem *mem;

	SYS_SLIST_FOR_EACH_CONTAINER(&tp_mem, mem, next) {
		tp_dbg("len=%zu %s:%d", mem->size, mem->file, mem->line);
	}
}

