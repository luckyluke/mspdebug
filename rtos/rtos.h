/* MSPDebug - debugging tool for MSP430 MCUs
 * Copyright (C) 2009, 2010 Daniel Beer
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef RTOS_H_
#define RTOS_H_

#include "gdb_proto.h"

#define MAX_SYMBOL_LEN 20
#define MAX_NAME_LEN   64

struct rtos_symbol {
	char name[10];
	uint32_t addr;
};

struct rtos_thread {
	char *name;
	uint64_t id;
	char *extra_info;
};

struct rtos_data {
	char name[10];
	struct rtos_symbol *symbols;
	struct rtos_thread *threads;
	unsigned int thread_count;
	uint64_t current_thread;
	uint64_t current_thread_id;
	int (*update_threads)(struct rtos_data *rtos);
	void *extra;
};

void rtos_init(void);
int rtos_handle_generic_cmd(struct gdb_data *data, char *buf, int *handled);

#endif  /* RTOS_H_ */
