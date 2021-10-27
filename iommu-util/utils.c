/*
 * acpi_decode.c: Helper routines to locate and map ACPI tables.
 *
 * Copyright (c) 2020, Ross Philipson ross.philipson@gmail.com
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *   * Neither the name of the Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include "defs.h"

#define EFI_LINE_SIZE 64

uint8_t *helper_mmap(size_t phys_addr, size_t length)
{
	uint32_t page_offset = phys_addr % sysconf(_SC_PAGESIZE);
	uint8_t *addr;
	int fd;

	fd = open("/dev/mem", O_RDONLY);
	if (fd == -1)
		return NULL;

	addr = (uint8_t*)mmap(0, page_offset + length, PROT_READ, MAP_PRIVATE, fd, phys_addr - page_offset);
	close(fd);

	if (addr == MAP_FAILED)
		return NULL;

	return addr + page_offset;
}

void helper_unmmap(uint8_t *addr, size_t length)
{
	uint32_t page_offset = (size_t)addr % sysconf(_SC_PAGESIZE);

	munmap(addr - page_offset, length + page_offset);
}

int helper_efi_locate(const char *efi_entry, uint32_t length, size_t *location)
{
	FILE *systab = NULL;
	char efiline[EFI_LINE_SIZE];
	char *val;
	off_t loc = 0;

	*location = 0;

	/* use EFI tables if present */
	systab = fopen("/sys/firmware/efi/systab", "r");
	if (systab == NULL)
		return -1;

	while((fgets(efiline, EFI_LINE_SIZE - 1, systab)) != NULL) {
		if (strncmp(efiline, efi_entry, 6) == 0) {
			/* found EFI entry, get the associated value */
			val = memchr(efiline, '=', strlen(efiline)) + 1;
			loc = strtol(val, NULL, 0);
			break;
		}
	}
	fclose(systab);

	if (loc != 0) {
		*location = loc;
		return 0;
	}

	return -1;
}
