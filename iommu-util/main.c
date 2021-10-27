/*
 * main.c:
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
#include <getopt.h>
#include "defs.h"

static struct option long_options[] = {
	{"dmar", no_argument, 0, 'd'},
	{"dmar-file", required_argument, 0, 'D'},
	{"ivrs", no_argument, 0, 'i'},
	{"ivrs-file", required_argument, 0, 'I'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0}
};

static void
usage(void)
{
	printf("Usage:\n");
	printf("-d, --dmar               read Intel DMAR ACPI table from memory and decode\n");
	printf("-D, --dmar-file <file>   read Intel DMAR ACPI table from file and decode\n");
	printf("-i, --ivrs               read AMD IVRS ACPI table from memory and decode\n");
	printf("-I, --ivrs-file <file>   read AMD IVRS ACPI table from file and decode\n");
	printf("-h, --help               prints this message\n");
}

int
main(int argc, char *argv[])
{
	int c;
	int option_index = 0;

	if (argc <= 1) {
		usage();
		exit(-1);
	}

	for ( ; ; ) {
		c = getopt_long(argc, argv, "dD:iI:h", long_options, &option_index);
		if ( c == -1 )
			break;

		switch (c) {
		case 'd':
			decode_dmar_table();
			break;
		case 'D':
			decode_dmar_table_file(optarg);
			break;
		case 'i':
			/* TODO */
			break;
		case 'I':
			/* TODO */
			break;
		case 'h':
			usage();
			break;
		case '?':
			usage();
			break;
		default:
			abort();
		}
	}

	return 0;
}
