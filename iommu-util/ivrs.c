/*
 * ivrs.c: Routines to scan and print IVRS table.
 *
 * Copyright (c) 2021, Oracle and/or its affiliates.
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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "defs.h"

void
decode_ivrs_table(void)
{
	struct acpi_table_header *table = NULL;
	int rc;

	printf("IVRS decode utility - reading memory\n");

	table = (struct acpi_table_header *)malloc(ACPI_MAX_BUF);
	if (!table) {
		printf("Allocation failure\n");
		goto done;
	}

	/* read the local host's ACPI tables */
	rc = acpi_get_table(ACPI_SIG_DMAR, (uint8_t*)table, ACPI_MAX_BUF);
	if (rc != 0) {
		printf("Failed to read host IVRS\n");
		goto done;
	}

	/* TODO acpi_parse_dmar(table);*/

done:
	if (table != NULL)
		free(table);
}

void
decode_ivrs_table_file(const char *file)
{
	struct acpi_table_header *table = NULL;
	FILE *infile = NULL;
	struct stat instat;
	size_t rd;

	if (stat(file, &instat) != 0) {
		printf("Stat failed for %s\n", file);
		exit(-1);
	}

	printf("IVRS decode utility - reading input file IVRS: %s size: %d\n",
	       file, (int)instat.st_size);

	table = (struct acpi_table_header *)malloc((size_t)instat.st_size);
	if (!table) {
		printf("Allocation failure\n");
		goto done;
	}

	infile = fopen(file, "rb");
	if (!infile) {
		printf("Could not open %s\n", file);
		goto done;
	}

	rd = fread(table, 1, (size_t)instat.st_size, infile);
	if (rd != (size_t)instat.st_size) {
		printf("Failure - only read %d\n", (int)rd);
		goto done;
	}

	/* TOOD acpi_parse_ivrs(table);*/

done:
	if (table != NULL)
		free(table);
	if (infile != NULL)
		fclose(infile);
}
