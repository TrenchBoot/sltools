/*
 * acpi_decode.c: Definitions for dmardump utility.
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

#ifndef __DEFS_H__
#define __DEFS_H__

#if __WORDSIZE == 64
#define INT_FMT "%ld"
#define UINT_FMT "%lx"
#else
#define INT_FMT "%d"
#define UINT_FMT "%x"
#endif

#define ACPI_SIG_DMAR	"DMAR"	/* DMA Remapping table */
#define ACPI_SIG_IVRS	"IVRS"	/* I/O Virtualization Reporting Structure table */

#define ACPI_NAME_SIZE		4
#define ACPI_OEM_ID_SIZE	6
#define ACPI_OEM_TABLE_ID_SIZE	8

#define ACPI_MAX_BUF		4*4096 /* should be enough room for any ACPI table here */

struct acpi_table_header {
	char signature[ACPI_NAME_SIZE];	/* ASCII table signature */
	uint32_t length;		/* Length of table in bytes, including this header */
	uint8_t revision;		/* ACPI Specification minor version # */
	uint8_t checksum;		/* To make sum of entire table == 0 */
	char oem_id[ACPI_OEM_ID_SIZE];	/* ASCII OEM identification */
	char oem_table_id[ACPI_OEM_TABLE_ID_SIZE];	/* ASCII OEM table identification */
	uint32_t oem_revision;			/* OEM revision number */
	char asl_compiler_id[ACPI_NAME_SIZE];	/* ASCII ASL compiler vendor ID */
	uint32_t asl_compiler_revision;		/* ASL compiler version */
};

uint8_t *helper_mmap(size_t phys_addr, size_t length);
void helper_unmmap(uint8_t *addr, size_t length);
int helper_efi_locate(const char *efi_entry, uint32_t length, size_t *location);

int acpi_get_table(const char *sig, uint8_t *buf, uint32_t length);

void decode_dmar_table(void);
void decode_dmar_table_file(const char *file);

void decode_ivrs_table(void);
void decode_ivrs_table_file(const char *file);

#endif /* __DEFS_H__ */
