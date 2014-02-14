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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "util.h"
#include "device.h"
#include "gdb_proto.h"
#include "chibios.h"

/**
 * @brief   ChibiOS/RT memory signature record.
 * Copied from os/kernel/include/chregistry.h of ChibiOS 2.6.2
 */
typedef struct {
  char      ch_identifier[4];       /**< @brief Always set to "main".       */
  uint8_t   ch_zero;                /**< @brief Must be zero.               */
  uint8_t   ch_size;                /**< @brief Size of this structure.     */
  uint16_t  ch_version;             /**< @brief Encoded ChibiOS/RT version. */
  uint8_t   ch_ptrsize;             /**< @brief Size of a pointer.          */
  uint8_t   ch_timesize;            /**< @brief Size of a @p systime_t.     */
  uint8_t   ch_threadsize;          /**< @brief Size of a @p Thread struct. */
  uint8_t   cf_off_prio;            /**< @brief Offset of @p p_prio field.  */
  uint8_t   cf_off_ctx;             /**< @brief Offset of @p p_ctx field.   */
  uint8_t   cf_off_newer;           /**< @brief Offset of @p p_newer field. */
  uint8_t   cf_off_older;           /**< @brief Offset of @p p_older field. */
  uint8_t   cf_off_name;            /**< @brief Offset of @p p_name field.  */
  uint8_t   cf_off_stklimit;        /**< @brief Offset of @p p_stklimit
                                                field.                      */
  uint8_t   cf_off_state;           /**< @brief Offset of @p p_state field. */
  uint8_t   cf_off_flags;           /**< @brief Offset of @p p_flags field. */
  uint8_t   cf_off_refs;            /**< @brief Offset of @p p_refs field.  */
  uint8_t   cf_off_preempt;         /**< @brief Offset of @p p_preempt
                                                field.                      */
  uint8_t   cf_off_time;            /**< @brief Offset of @p p_time field.  */
} chdebug_t;

/**
 * @name    Thread states
 * Copied from os/kernel/include/chthreads.h of ChibiOS 2.6.2
 */
#define THD_STATE_READY         0   /**< @brief Waiting on the ready list.  */
#define THD_STATE_CURRENT       1   /**< @brief Currently running.          */
#define THD_STATE_SUSPENDED     2   /**< @brief Created in suspended state. */
#define THD_STATE_WTSEM         3   /**< @brief Waiting on a semaphore.     */
#define THD_STATE_WTMTX         4   /**< @brief Waiting on a mutex.         */
#define THD_STATE_WTCOND        5   /**< @brief Waiting on a condition
                                         variable.                          */
#define THD_STATE_SLEEPING      6   /**< @brief Waiting in @p chThdSleep()
                                         or @p chThdSleepUntil().           */
#define THD_STATE_WTEXIT        7   /**< @brief Waiting in @p chThdWait().  */
#define THD_STATE_WTOREVT       8   /**< @brief Waiting for an event.       */
#define THD_STATE_WTANDEVT      9   /**< @brief Waiting for several events. */
#define THD_STATE_SNDMSGQ       10  /**< @brief Sending a message, in queue.*/
#define THD_STATE_SNDMSG        11  /**< @brief Sent a message, waiting
                                         answer.                            */
#define THD_STATE_WTMSG         12  /**< @brief Waiting for a message.      */
#define THD_STATE_WTQUEUE       13  /**< @brief Waiting on an I/O queue.    */
#define THD_STATE_FINAL         14  /**< @brief Thread terminated.          */

#define THD_STATE_UNKNOWN       15

/* Assume 16 bit, little endian */
#define regmsp_t uint16_t

/**
 * @brief   System saved context.
 * @details This structure represents the inner stack frame during a context
 *          switching.
 * Copied from os/ports/GCC/MSP430/chcore.h
 */
struct intctx {
  regmsp_t      r4;
  regmsp_t      r5;
  regmsp_t      r6;
  regmsp_t      r7;
  regmsp_t      r8;
  regmsp_t      r9;
  regmsp_t      r10;
  regmsp_t      r11;
  regmsp_t      pc;
};


static char *thread_state_names[] = {"READY",
									 "CURRENT",
									 "SUSPENDED",
									 "WTSEM",
									 "WTMTX",
									 "WTCOND",
									 "SLEEPING",
									 "WTEXIT",
									 "WTOREVT",
									 "WTANDEVT",
									 "SNDMSGQ",
									 "SNDMSG",
									 "WTMSG",
									 "WTQUEUE",
									 "FINAL",
									 "UNKNOWN"};

struct rtos_symbol chibios_symbols[4] = {{"rlist", 0},
										 {"ch_debug", 0},
										 {"chSysInit", 0},
										 {"", 0}};

struct rtos_data chibios_data = {"ChibiOS",
								 chibios_symbols,
								 NULL,
								 0,
								 0,
								 -1,
								 chibios_update_threads,
								 chibios_get_thread_regs,
								 NULL};


int readaddr(uint16_t addr, uint16_t* dest)
{
	uint8_t buf[2];

	if (device_readmem(addr, buf, 2) < 0)
		return -1;

	*dest = *((uint16_t*)buf);
	return 0;
}

int chibios_update_debug(struct rtos_data *rtos)
{
	chdebug_t *debug;

	if (!rtos)
		return -1;

	if (rtos->extra)
		free(rtos->extra);

	rtos->extra = malloc(sizeof(chdebug_t));
	if (!rtos->extra)
		return -1;

	if (device_readmem(rtos->symbols[1].addr,
					   rtos->extra, sizeof(chdebug_t)) < 0) {
		free(rtos->extra);
		rtos->extra = NULL;
		return -1;
	}

	debug = rtos->extra;

	if (strncmp(debug->ch_identifier, "main", 4)) {
		return -1;
	}

	if (debug->ch_size < sizeof(chdebug_t)) {
		return -1;
	}

	return 0;
}

int chibios_update_threads(struct rtos_data *rtos)
{
	uint16_t rlist;
	uint16_t current, previous, older;
	int nfound=0;
	chdebug_t* debug;

	if (!rtos)
		return -1;

	if (chibios_update_debug(rtos) < 0)
		return -1;

	debug = (chdebug_t*)rtos->extra;

	if (rtos->threads) {
		int i;
		for (i=0; i<rtos->thread_count; i++) {
			if (rtos->threads[i].name)
				free(rtos->threads[i].name);
			if (rtos->threads[i].extra_info)
				free(rtos->threads[i].extra_info);
		}
		free(rtos->threads);
		rtos->threads = NULL;
		rtos->thread_count = 0;
	}

	// find the number of threads in the system, if any
	rlist = rtos->symbols[0].addr;
	current = previous = rlist;
	while (1) {
		if (readaddr(current + debug->cf_off_newer, &current) < 0)
			return -2;

		if (current == 0){
			nfound = -1;
			break;
		}

		if (readaddr(current + debug->cf_off_older, &older) < 0)
			return -3;

		// integrity check
		if ((older == 0) || (older != previous)){
			nfound = -1;
			break;
		}

		if (current == rlist)
			break;

		nfound++;
		previous = current;
	}

	if (nfound <= 0){
		// RTOS not yet active?
		rtos->threads = malloc(sizeof(struct rtos_thread));
		memset(rtos->threads, 0, sizeof(struct rtos_thread));
		rtos->threads[0].id = 1;
		rtos->threads[0].name = malloc(18);
		if (rtos->threads[0].name == NULL)
			return -2;
		rtos->threads[0].extra_info = malloc(15);
		if (rtos->threads[0].extra_info == NULL)
			return -2;
		strcpy(rtos->threads[0].name, "Current Execution");
		strcpy(rtos->threads[0].extra_info, "No RTOS Thread");
		rtos->thread_count = 1;
		rtos->current_thread = 1;

	} else {
		rtos->threads = malloc(sizeof(struct rtos_thread)*nfound);
		memset(rtos->threads, 0, sizeof(struct rtos_thread)*nfound);

		// find information about each thread found before
		struct rtos_thread *cur_thd=rtos->threads;
		while (cur_thd < rtos->threads + nfound) {
			uint16_t name_ptr;
			unsigned char state;
			char name_tmp[MAX_NAME_LEN];

			if (readaddr(current + debug->cf_off_newer, &current) < 0)
				return -2;
			if (current == rlist)
				break;

			cur_thd->id = (uint64_t)current;

			if (readaddr(current + debug->cf_off_name, &name_ptr) < 0)
				return -3;
			if (device_readmem(name_ptr, (unsigned char*)name_tmp, MAX_NAME_LEN) < 0)
				return -4;
			name_tmp[MAX_NAME_LEN - 1] = '\x00';
			if (name_tmp[0] == '\x00')
				strcpy(name_tmp, "No Name");

			cur_thd->name = malloc(strlen(name_tmp) + 1);
			if (!cur_thd->name)
				return -5;
			sprintf(cur_thd->name, "%s", name_tmp);

			if (device_readmem(current + debug->cf_off_state, &state, 1) < 0)
				return -3;
			if (state > THD_STATE_FINAL)
				state = THD_STATE_UNKNOWN;

			cur_thd->extra_info = malloc(strlen(thread_state_names[state]) + 1);
			if (!cur_thd->extra_info)
				return -5;
			sprintf(cur_thd->extra_info, "%s", thread_state_names[state]);

			cur_thd++;
		}
		rtos->thread_count = nfound;

		/* cf_off_name equals to readylist_current_offset */
		if (readaddr(rlist + debug->cf_off_name, &current) < 0)
			return -2;

		rtos->current_thread = current;
	}

	return rtos->thread_count;
}

int chibios_get_thread_regs(struct rtos_data *rtos, uint64_t tid, address_t *regs)
{
	int i;
	uint16_t sp;
	chdebug_t *debug;
	//uint16_t intctx[9];
	struct intctx ctx;

	if (!regs)
		return -1;

	if (!rtos)
		return -1;

	if (chibios_update_debug(rtos) < 0)
		return -1;

	debug = (chdebug_t*)rtos->extra;

	if (readaddr(tid + debug->cf_off_ctx, &sp) < 0)
		return -1;

	if (device_readmem(sp, (uint8_t*)&ctx, sizeof(struct intctx)) < 0)
		return -1;

	/* printf("tid %"PRIu64" sp %x\n", tid, sp); */

	for (i=0; i<DEVICE_NUM_REGS; i++){
		regs[i] = ADDRESS_NONE;
	}

	regs[0] = ctx.pc;
	regs[1] = sp + sizeof(struct intctx);
	regs[4] = ctx.r4;
	regs[5] = ctx.r5;
	regs[6] = ctx.r6;
	regs[7] = ctx.r7;
	regs[8] = ctx.r8;
	regs[9] = ctx.r9;
	regs[10] = ctx.r10;
	regs[11] = ctx.r11;

	/* for (i=0; i<DEVICE_NUM_REGS; i++){ */
	/* 	printf("reg %d val %04x\n", i, regs[i]); */
	/* } */

	return 0;
}
