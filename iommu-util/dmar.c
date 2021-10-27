/*
 * dmar.c: Routines to scan and print DMAR table.
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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "defs.h"

#define ACPI_NAME_SIZE		4
#define ACPI_OEM_ID_SIZE	6
#define ACPI_OEM_TABLE_ID_SIZE	8

#define BITS_PER_LONG		32
#define BITS_TO_LONGS(bits) \
	(((bits)+BITS_PER_LONG-1)/BITS_PER_LONG)
#define DECLARE_BITMAP(name,bits) \
	unsigned long name[BITS_TO_LONGS(bits)]

#define MIN_SCOPE_LEN (sizeof(struct acpi_pci_path) + \
	sizeof(struct acpi_dev_scope))

#define DMAR_MAX_BUF		4096 /* should be enough room for any DMAR */

#define DRHD_FLAGS_INCLUDE_ALL	0x1       /* drhd remaps remaining devices */

#define DMAR_TYPE	1
#define RMRR_TYPE	2
#define ATSR_TYPE	3

enum acpi_dmar_entry_type {
	ACPI_DMAR_DRHD = 0,
	ACPI_DMAR_RMRR,
	ACPI_DMAR_ATSR,
	ACPI_DMAR_ENTRY_COUNT
};

/* Values for entry_type in struct acpi_dmar_device_scope */

enum acpi_dmar_scope_type {
	ACPI_DMAR_SCOPE_TYPE_NOT_USED = 0,
	ACPI_DMAR_SCOPE_TYPE_ENDPOINT = 1,
	ACPI_DMAR_SCOPE_TYPE_BRIDGE = 2,
	ACPI_DMAR_SCOPE_TYPE_IOAPIC = 3,
	ACPI_DMAR_SCOPE_TYPE_HPET = 4,
	ACPI_DMAR_SCOPE_TYPE_RESERVED = 5	/* 5 and greater are reserved */
};

enum acpi_dev_scope_type {
	ACPI_DEV_ENDPOINT=0x01,	/* PCI Endpoing device */
	ACPI_DEV_P2PBRIDGE,	/* PCI-PCI Bridge */
	ACPI_DEV_IOAPIC,	/* IOAPIC device*/
	ACPI_DEV_MSI_HPET,	/* MSI capable HPET*/
	ACPI_DEV_ENTRY_COUNT
};

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

struct acpi_table_dmar {
	struct acpi_table_header header;	/* Common ACPI table header */
	uint8_t width;				/* Host Address Width */
	uint8_t flags;
	uint8_t reserved[10];
};

struct acpi_dmar_entry_header {
	uint16_t type;
	uint16_t length;
} __attribute__((packed));

struct dmar_scope {
	DECLARE_BITMAP(buses, 256);	/* buses owned by this unit */
	uint16_t *devices;		/* devices owned by this unit */
	int devices_cnt;
};

struct acpi_table_drhd {
	struct	acpi_dmar_entry_header header;
	uint8_t	flags;
	uint8_t	reserved;
	uint16_t segment;
	uint64_t address; /* register base address for this drhd */
} __attribute__ ((packed));

struct acpi_table_rmrr {
	struct acpi_dmar_entry_header header;
	uint16_t reserved;
	uint16_t segment;
	uint64_t base_address;
	uint64_t end_address;
} __attribute__ ((packed));

struct acpi_table_atsr {
	struct acpi_dmar_entry_header header;
	uint8_t flags;
	uint8_t reserved;
	uint16_t segment;
} __attribute__ ((packed));

struct acpi_dev_scope {
	uint8_t dev_type;
	uint8_t length;
	uint8_t	reserved[2];
	uint8_t enum_id;
	uint8_t start_bus;
} __attribute__((packed));

struct acpi_pci_path {
	uint8_t dev;
	uint8_t fn;
} __attribute__((packed));

static int g_include_all = 0;
static int g_all_ports = 0;

/*
 * Count number of devices in device scope.  Do not include PCI sub
 * hierarchies.
 */
static int
scope_device_count(void *start, void *end)
{
	struct acpi_dev_scope *scope;
	int count = 0;

	while ( start < end ) {
		scope = start;
		if (scope->length < MIN_SCOPE_LEN) {
			printf("*** INVALID device scope - length 0x%2.2x less than minimum 0x%2.2x\n",
				scope->length, (uint32_t)MIN_SCOPE_LEN);
			return -1;
		}

		if (scope->dev_type >= ACPI_DEV_ENTRY_COUNT) {
			printf("*** INVALID device scope - invalid device type 0x%2.2x\n", scope->dev_type);
			return -1;
		}

		if ( scope->dev_type == ACPI_DEV_ENDPOINT ||
			scope->dev_type == ACPI_DEV_IOAPIC ||
			scope->dev_type == ACPI_DEV_MSI_HPET )
			count++;

		start += scope->length;
	}

	return count;
}

static void
acpi_parse_dev_scope(void *start, void *end, int type)
{
	struct acpi_dev_scope *acpi_scope;
	struct acpi_pci_path *path;
	uint16_t bus;
	int depth = 0;
	int i = 1;
	const char *enumstr = "Reserved";

	if (scope_device_count(start, end) < 0 )
		return;

	while ( start < end ) {
		printf("    Device Scope Structure #%d\n", i++);
		printf("    ==========================\n");

		acpi_scope = start;
		path = (struct acpi_pci_path *)(acpi_scope + 1);
		depth = (acpi_scope->length - sizeof(struct acpi_dev_scope))
			/ sizeof(struct acpi_pci_path);
		bus = acpi_scope->start_bus;

		switch ( acpi_scope->dev_type ) {
		case ACPI_DEV_P2PBRIDGE:
			printf("    Type:           0x%2.2x (ACPI_DEV_P2PBRIDGE)\n", acpi_scope->dev_type);
			break;
		case ACPI_DEV_MSI_HPET:
			printf("    Type:           0x%2.2x (ACPI_DEV_MSI_HPET)\n", acpi_scope->dev_type);
			break;
		case ACPI_DEV_ENDPOINT:
			printf("    Type:           0x%2.2x (ACPI_DEV_ENDPOINT)\n", acpi_scope->dev_type);
			break;
		case ACPI_DEV_IOAPIC:
			printf("    Type:           0x%2.2x (ACPI_DEV_IOAPIC)\n", acpi_scope->dev_type);
			enumstr = "I/O APICID";
			break;
		}
		printf("    Length:         0x%2.2x\n", acpi_scope->length);
		printf("    Reserved:       %2.2x %2.2x\n", acpi_scope->reserved[0], acpi_scope->reserved[1]);
		printf("    Enumeration ID: 0x%2.2x - %s\n", acpi_scope->enum_id, enumstr);
		printf("    Start Bus Num:  0x%2.2x\n", bus);
		printf("    Path Depth = %d, Path Entries:\n", depth);

		while ( depth-- > 0 ) {
			printf("       -- Device: 0x%2.2x Function: 0x%2.2x\n", path->dev, path->fn);
			path++;
		}

		start += acpi_scope->length;
	}
}

static void
acpi_parse_one_drhd(struct acpi_dmar_entry_header *header)
{
	struct acpi_table_drhd *drhd = (struct acpi_table_drhd *)header;
	void *dev_scope_start, *dev_scope_end;
	int include_all = 0;

	include_all = drhd->flags & 1; /* BIT0: INCLUDE_ALL */

	printf("Flags:          0x%2.2x  -- INCLUDE_ALL = %s\n", drhd->flags, (include_all == 1 ? "yes" : "no"));
	printf("Reserved:       0x%2.2x\n", drhd->reserved);
	printf("Segment Number: 0x%4.4x\n", drhd->segment);
	printf("Register Base:  0x%lx\n", drhd->address);

	if (g_include_all != 0) {
		if (include_all != 0) {
			printf("*** INVALID DRHD - only one INCLUDE_ALL unit allowed!\n");
		}
	} else
		g_include_all = include_all;

	dev_scope_start = (void *)(drhd + 1);
	dev_scope_end = ((void *)drhd) + header->length;
	acpi_parse_dev_scope(dev_scope_start, dev_scope_end, DMAR_TYPE);
}

static void
acpi_parse_one_rmrr(struct acpi_dmar_entry_header *header)
{
	struct acpi_table_rmrr *rmrr = (struct acpi_table_rmrr *)header;
	void *dev_scope_start, *dev_scope_end;

	printf("Reserved:       0x%4.4x\n", rmrr->reserved);
	printf("Segment Number: 0x%4.4x\n", rmrr->segment);
	printf("Base Address:   0x%lx\n", rmrr->base_address);
	printf("End Address:    0x%lx\n", rmrr->end_address);

	if ( rmrr->base_address >= rmrr->end_address ) {
		printf("*** INVALIDE RMRR - base address 0x%lx is greater than the end address 0x%lx\n",
			rmrr->base_address, rmrr->end_address);
	}

	dev_scope_start = (void *)(rmrr + 1);
	dev_scope_end   = ((void *)rmrr) + header->length;
	acpi_parse_dev_scope(dev_scope_start, dev_scope_end, RMRR_TYPE);
}

static void
acpi_parse_one_atsr(struct acpi_dmar_entry_header *header)
{
	struct acpi_table_atsr *atsr = (struct acpi_table_atsr *)header;
	int all_ports;
	void *dev_scope_start, *dev_scope_end;

	all_ports = atsr->flags & 1; /* BIT0: ALL_PORTS */

	printf("Flags:          0x%2.2x  -- ALL_PORTS = %s\n", atsr->flags, (all_ports == 1 ? "yes" : "no"));
	printf("Reserved:       0x%2.2x\n", atsr->reserved);
	printf("Segment Number: 0x%4.4x\n", atsr->segment);

	if ( !all_ports ) {
		dev_scope_start = (void *)(atsr + 1);
		dev_scope_end   = ((void *)atsr) + header->length;
		acpi_parse_dev_scope(dev_scope_start, dev_scope_end, ATSR_TYPE);
	}

	if (g_all_ports != 0) {
		if (all_ports != 0)
			printf("*** INVALID ATSR - only one ALL_PORTS structure allowed!\n");
	} else
		g_all_ports = all_ports;
}

static void
acpi_parse_dmar(struct acpi_table_header *table)
{
	struct acpi_table_dmar *dmar;
	struct acpi_dmar_entry_header *entry_header;
	int i = 1, j = 1, k = 1, l = 1;
	uint8_t *p;

	dmar = (struct acpi_table_dmar *)table;

	printf("DMA Remapping Reporting Structure\n");
	printf("==================================================\n");
	printf("Signature:        %.4s\n", dmar->header.signature);
	printf("Length:           0x%8.8x\n", dmar->header.length);
	printf("Revision:         0x%2.2x\n", dmar->header.revision);
	printf("Checksum:         0x%2.2x\n", dmar->header.checksum);
	printf("OEMID:            %.*s\n", ACPI_OEM_ID_SIZE, dmar->header.oem_id);
	printf("OEM Table ID:     %.*s\n", ACPI_OEM_TABLE_ID_SIZE, dmar->header.oem_table_id);
	printf("OEM Revision:     0x%8.8x\n", dmar->header.oem_revision);
	printf("Creator ID:       %.*s\n", ACPI_NAME_SIZE, dmar->header.asl_compiler_id);
	printf("Creator Revision: 0x%8.8x\n", dmar->header.asl_compiler_revision);
	printf("HAW:              0x%2.2x\n", dmar->width);
	printf("Flags:            0x%2.2x\n", dmar->flags);

	p = &dmar->reserved[0];
	printf("Reserved[10]: %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x\n",
	  p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9]);

	if (!dmar->width)
		printf("*** Invalid DMAR width of zero\n");

	printf("\nRemapping Structures...\n\n");

	entry_header = (struct acpi_dmar_entry_header *)(dmar + 1);

	while ( ((unsigned long)entry_header) <
	   (((unsigned long)dmar) + table->length) ) {
		switch ( entry_header->type ) {
		case ACPI_DMAR_DRHD:
			printf("DMA Remapping Hardware Unit Definition (DRHD) Structure #%d\n", i++);
			printf("Type:           0x%4.4x (ACPI_DMAR_DRHD)\n", entry_header->type);
			printf("Length:         0x%4.4x\n", entry_header->length);
			acpi_parse_one_drhd(entry_header);
			printf("\n");
			break;
		case ACPI_DMAR_RMRR:
			printf("Reserved Memory Region Reporting (RMRR) Structure #%d\n", j++);
			printf("Type:           0x%4.4x (ACPI_DMAR_RMRR)\n", entry_header->type);
			printf("Length:         0x%4.4x\n", entry_header->length);
			acpi_parse_one_rmrr(entry_header);
			printf("\n");
			break;
		case ACPI_DMAR_ATSR:
			printf("Root Port ATS Capability Reporting (ATSR) Structure #%d\n", k++);
			printf("Type:           0x%4.4x (ACPI_DMAR_ATSR)\n", entry_header->type);
			printf("Length:         0x%4.4x\n", entry_header->length);
			acpi_parse_one_atsr(entry_header);
			printf("\n");
			break;
		default:
			printf("Unknown Reporting Structure #%d\n", l++);
			printf("Type:           0x%4.4x (UNKNOWN)\n", entry_header->type);
			printf("Length:         0x%4.4x\n", entry_header->length);
			printf("\n");
			break;
		}

		entry_header = ((void *)entry_header + entry_header->length);
	}

	printf("==================================================\n");
	printf("End DMAR\n");
}

void
decode_dmar_table(void)
{
	struct acpi_table_header *table = NULL;
	int rc;

	printf("DMAR dump utility - reading memory\n");

	table = (struct acpi_table_header *)malloc(DMAR_MAX_BUF);
	if (!table) {
		printf("Allocation failure\n");
		goto done;
	}

	/* read the local host's ACPI tables */
	rc = acpi_get_table(ACPI_SIG_DMAR, (uint8_t*)table, DMAR_MAX_BUF);
	if (rc != 0) {
		printf("Failed to read host DMAR\n");
		goto done;
	}

	acpi_parse_dmar(table);

done:
	if (table != NULL)
		free(table);
}

void
decode_dmar_table_file(const char *file)
{
	struct acpi_table_header *table = NULL;
	FILE *infile = NULL;
	struct stat instat;
	size_t rd;

	if (stat(file, &instat) != 0) {
		printf("Stat failed for %s\n", file);
		exit(-1);
	}

	printf("DMAR dump utility - reading input file DMAR: %s size: %d\n",
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

	acpi_parse_dmar(table);

done:
	if (table != NULL)
		free(table);
	if (infile != NULL)
		fclose(infile);
}
