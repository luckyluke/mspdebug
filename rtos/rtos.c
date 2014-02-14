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

#include "rtos.h"
#include "util.h"
#include "device.h"
#include "chibios.h"
#include "gdb_proto.h"
#include "output.h"

static struct rtos_data *rtos=NULL;

static int gdb_to_hex_string(const char *s, char *hex_s, ssize_t len);
static int gdb_from_hex_string(const char *hex_s, char *s, ssize_t len);
static char* rtos_next_symbol(struct rtos_data *rdata, char* cur_sym, uint32_t addr);
static int rtos_qsymbol(struct gdb_data *data, char *buf);

static int gdb_to_hex_string(const char *s, char *hex_s, ssize_t len)
{
	int i, j=0;

	if ((!s) || (!hex_s) || (len <=0))
		return -1;

	for (i=0; i<len; i++) {
		j += snprintf(hex_s + (2*i), 3, "%02x", s[i]);
	}
	return j;
}

static int gdb_from_hex_string(const char *hex_s, char *s, ssize_t len)
{
	int i, j=0;

	if ((!s) || (!hex_s) || (len <=0))
		return -1;

	for (i=0; i<len; i++) {
		j += sscanf(hex_s + (2*i), "%02x", (unsigned int*)&(s[i]));
	}
	return j;
}

void rtos_init(void)
{
	rtos = &chibios_data;
}

static char* rtos_next_symbol(struct rtos_data *rdata, char* cur_sym, uint32_t addr)
{
	struct rtos_symbol *s;

	if ((!rdata) || (!rdata->symbols))
		return NULL;

	if (!cur_sym)
		return rdata->symbols[0].name;

	for (s=rdata->symbols; strlen(s->name) > 0 ; s++) {
		if (!strncmp(s->name, cur_sym, MAX_SYMBOL_LEN)) {
			s->addr = addr;
			s++;
			if (strlen(s->name) == 0)
				return NULL;
			return s->name;
		}
	}
	return NULL;
}

static int rtos_qsymbol(struct gdb_data *data, char *buf)
{
	uint32_t addr=0;
	char cur_sym[MAX_SYMBOL_LEN];
	char hexs[2*MAX_SYMBOL_LEN + 1];
	char *next_sym;
	char response[2*MAX_SYMBOL_LEN + 8];

	if (!rtos)
		return gdb_send(data, "OK");

	/* Decode any symbol name in the packet*/
	cur_sym[0] = '\x00';
	gdb_from_hex_string(strchr(buf + 8, ':') + 1, cur_sym, MAX_SYMBOL_LEN);

	if ((strcmp(buf, "qSymbol::") != 0) &&
		(!sscanf(buf, "qSymbol:%04x:", (unsigned int*)&addr))) {
		/* symbol not found */
		printc("RTOS not detected!\n");
		rtos = NULL;
		return gdb_send(data, "OK");
	}

	if (addr > 0) {
		// symbol found
		// ask next symbol if any
		if ((next_sym = rtos_next_symbol(rtos, cur_sym, addr)) != NULL){
			gdb_to_hex_string(next_sym, hexs, strlen(next_sym));
			snprintf(response, 8+strlen(hexs)+1, "qSymbol:%s", hexs);
			return gdb_send(data, response);
		}
		// all symbols have been found!
		printc("RTOS %s detected!\n", rtos->name);
		return gdb_send(data, "OK");

	} else {
		// symbol not found
		// ask first symbol if any
		next_sym = rtos_next_symbol(rtos, NULL, addr);
		// should check for next rtos
		//if ((next_sym == NULL) && (++rtos == NULL))
		if (next_sym == NULL)
			return gdb_send(data, "OK");
		gdb_to_hex_string(next_sym, hexs, strlen(next_sym));
		snprintf(response, 8+strlen(hexs)+1, "qSymbol:%s", hexs);
		return gdb_send(data, response);
	}
}


/* RTOS specific packets may be query (q), thread alive (T)
 * read registers (g) or set thread (H) */
int rtos_handle_generic_cmd(struct gdb_data *data, char *buf, int *handled)
{
	*handled = 1;

	/* Read registers */
	if (!strncmp(buf, "g", 1)) {
		if (rtos) {
			if ((rtos->current_thread_id != -1) &&
				(rtos->current_thread_id != rtos->current_thread)) {

				address_t regs[DEVICE_NUM_REGS];
				char buf[DEVICE_NUM_REGS*4+1];
				int i;

				if (rtos->get_thread_regs(rtos, rtos->current_thread_id, regs) < 0)
					return gdb_send(data, "E00");

				for (i=0; i<DEVICE_NUM_REGS; i++)
					if (regs[i] == ADDRESS_NONE)
						snprintf(buf+4*i, 5, "xxxx");
					else
						snprintf(buf+4*i, 5, "%02x%02x",
								 regs[i] & 0xff,
								 (regs[i] >> 8) & 0xff);

				buf[DEVICE_NUM_REGS*4] = '\x00';

				return gdb_send(data, buf);
			}
		}

		/* Query RTOS-specific symbol */
	} else if (!strncmp(buf, "qSymbol", 7)) {
		return rtos_qsymbol(data, buf);

		/* Get full Thread list in one command*/
	} else if (!strncmp(buf, "qfThreadInfo", 12)) {
		if (rtos) {
			char *buf, *tmpbuf;
			int i;

			if (rtos->update_threads(rtos) < 0)
				return gdb_send(data, "E01");

			buf = malloc(17*rtos->thread_count + 1);
			if (buf == NULL)
				return gdb_send(data, "E01");

			tmpbuf = buf;
			tmpbuf += sprintf(tmpbuf, "m");
			for (i=0; i<rtos->thread_count; i++) {
				tmpbuf += sprintf(tmpbuf, "%" PRIx64, rtos->threads[i].id);
				if (i < (rtos->thread_count - 1))
					tmpbuf += sprintf(tmpbuf, ",");
			}

			i = gdb_send(data, buf);
			free(buf);
			return i;
		}

		/* Full thread list is sent with qfThreadInfo */
	} else if (!strncmp(buf, "qsThreadInfo", 12)) {
		return gdb_send(data, "l");

		/* Get Thread name and state */
	} else if (!strncmp(buf, "qThreadExtraInfo", 16)) {
		if (rtos) {
			uint64_t thid;
			int i;
			char *desc, *hexdesc;
			struct rtos_thread *th=NULL;

			if (!sscanf(buf, "qThreadExtraInfo,%" SCNx64, &thid))
				return gdb_send(data, "E01");

			for (i=0; i<rtos->thread_count; i++) {
				if (thid == rtos->threads[i].id) {
					th = &(rtos->threads[i]);
				}
			}
			if (th == NULL)
				return gdb_send(data, "E01");

			desc = malloc(strlen(th->name) + 3 + strlen(th->extra_info) + 1);
			if (desc == NULL)
				return gdb_send(data, "E01");

			sprintf(desc, "%s - %s", th->name, th->extra_info);

			hexdesc = malloc(2*MAX_NAME_LEN + 4);
			if (hexdesc == NULL){
				free(desc);
				return gdb_send(data, "E01");
			}

			if (gdb_to_hex_string(desc, hexdesc, strlen(desc))){
				int ret=gdb_send(data, hexdesc);
				free(hexdesc);
				free(desc);
				return ret;
			} else {
				return gdb_send(data, "E01");
			}
		}

		/* We attached to an existing process, no nultiprocessor */
	} else if (!strncmp(buf, "qAttached", 9)) {
		return gdb_send(data, "0");

		/* Send default relocation offsets */
	} else if (!strncmp(buf, "qOffsets", 8)) {
		return gdb_send(data, "Text=0;Data=0;Bss=0");

		/* Send current thread id */
	} else if (!strncmp(buf, "qC", 2)) {
		if (rtos) {
			char buf[19];
			if (rtos->update_threads(rtos) < 0)
				return gdb_send(data, "E01");

			snprintf(buf, 19, "QC%" PRIx64, rtos->current_thread);
			return gdb_send(data, buf);
		} else {
			return gdb_send(data, "QC0");
		}

		/* Set current Thread */
	} else if (buf[0] == 'H') {
		if (rtos) {
			uint64_t current;
			int i;

			if (rtos->update_threads(rtos) < 0)
				return gdb_send(data, "E01");

			if (buf[1] == 'g')
				sscanf(buf, "Hg%" SCNx64, &current);

			/* rtos->current_thread_id = current; */
			/* return gdb_send(data, "OK"); */

			for (i=0; i<rtos->thread_count; i++) {
				if (current == rtos->threads[i].id) {
					rtos->current_thread_id = current;
					return gdb_send(data, "OK");
				}
			}
			return gdb_send(data, "E01");
		}
		/* Check if Thread id alive */
	} else if (buf[0] == 'T') {
		if (rtos){
			uint64_t thid;
			int i;
			struct rtos_thread *th=NULL;

			if (rtos->update_threads(rtos) < 0)
				return gdb_send(data, "E01");

			if (!sscanf(buf, "T%" SCNx64, &thid))
				return gdb_send(data, "E01");

			for (i=0; i<rtos->thread_count; i++){
				if (thid == rtos->threads[i].id){
					th = &(rtos->threads[i]);
				}
			}

			if (th == NULL)
				return gdb_send(data, "E01");
			else
				return gdb_send(data, "OK");

		}
	}

	*handled = 0;
	return 0;
}
