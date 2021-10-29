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

#define IVRS_REV_FIXED	0x1
#define IVRS_REV_MIXED	0x2

struct acpi_table_ivrs {
	struct acpi_table_header header;	/* Common ACPI table header */
	uint32_t ivinfo;			/* IVRS IVinfo Field */
	uint8_t reserved[8];
	/* IVDBs */
} __attribute__((packed));

struct ivrs_ivinfo {
	union {
		uint32_t val;
		struct {
			uint32_t efr_sup:1;
			uint32_t dma_remap_sup:1;
			uint32_t reserved1:3;
			uint32_t gva_size:3;
			uint32_t pa_size:7;
			uint32_t va_size:7;
			uint32_t ht_ats_resv:1;
			uint32_t reserved2:9;
		};
	};
} __attribute__((packed));

struct ivrs_ivdb_common {
	uint8_t type;
	uint8_t flags;
	uint16_t length;
} __attribute__((packed));

#define IVHD_TYPE_10H	0x10
#define IVHD_TYPE_11H	0x11
#define IVHD_TYPE_40H	0x40

struct ivrs_ivhd {
	struct ivrs_ivdb_common ivdb;
	uint16_t devid;
	uint16_t cap_offset;
	uint64_t base_addr;	/* MMIO Address/BAR */
	uint16_t pci_seg;
	uint16_t iommu_info;
	uint32_t feature_info;
	/* Type 10 device entries */
	uint64_t efr_image;	/* Types 11h/40h only */
	uint64_t efr_image2;
	/* Type 11/40 device entries */
} __attribute__((packed));

struct ivhd_flags {
	union {
		uint8_t val;
		struct {
			uint8_t ht_tun_en:1;
			uint8_t pass_pw:1;
			uint8_t res_pass_pw:1;
			uint8_t isoc:1;
			uint8_t iotlb_sup:1;
			uint8_t coherent:1;
			uint8_t pre_f_sup:1; /* reserved for 11/40 */
			uint8_t ppr_sup:1;   /* reserved for 11/40 */
		};
	};
} __attribute__((packed));

#define IVMD_TYPE_ALL_PERIPHERALS	0x20
#define IVMD_TYPE_SPECIFIED_PERIPHERAL	0x21
#define IVMD_TYPE_PERIPHERAL_RANGE	0x22

struct ivrs_ivmd {
	struct ivrs_ivdb_common ivdb;
	uint16_t devid;
	uint16_t aux_data;
	uint64_t reserved;
	uint64_t start_addr;
	uint64_t mem_block_length;
} __attribute__((packed));

struct ivmd_flags {
	union {
		uint8_t val;
		struct {
			uint8_t unity:1;
			uint8_t ir:1;
			uint8_t iw:1;
			uint8_t excl_range:1;
			uint8_t reserved:4;
		};
	};
} __attribute__((packed));

static void
acpi_parse_one_ivhd(struct ivrs_ivdb_common *ivdb)
{
	struct ivrs_ivhd *ivhd = (struct ivrs_ivhd *)ivdb;
	struct ivhd_flags flags;

	printf("Device ID:            0x%4.4x\n", ivhd->devid);
	printf("Capabilities Offset:  0x%4.4x\n", ivhd->cap_offset);
	printf("Base Address:         0x%lx\n", ivhd->base_addr);
	printf("PCI Segment:          0x%4.4x\n", ivhd->pci_seg);
	printf("IOMMU Info:           0x%4.4x\n", ivhd->iommu_info);
	printf("Feature Info:         0x%8.8x\n", ivhd->feature_info);
	if (ivdb->type > IVHD_TYPE_10H) {
		printf("EFR Register Image:   0x%lx\n", ivhd->efr_image);
		printf("EFR Register Image 2: 0x%lx\n", ivhd->efr_image2);
	}

	printf("\n");

	flags.val = ivdb->flags;
	printf("  IVHD Flags\n");
	printf("  ---------------------------------\n");
	printf("    HtTunEn:          0x%1.1x\n", flags.ht_tun_en);
	printf("    PassPw:           0x%1.1x\n", flags.pass_pw);
	printf("    ResPassPw:        0x%1.1x\n", flags.res_pass_pw);
	printf("    Isoc:             0x%1.1x\n", flags.isoc);
	printf("    IotlbSup:         0x%1.1x\n", flags.iotlb_sup);
	printf("    Coherent:         0x%1.1x\n", flags.coherent);
	if (ivdb->type == IVHD_TYPE_10H) {
		printf("    PreFSup:          0x%1.1x\n", flags.pre_f_sup);
		printf("    PPRSup:           0x%1.1x\n", flags.ppr_sup);
	}
	printf("  ---------------------------------\n");
}

static void
acpi_parse_one_ivmd(struct ivrs_ivdb_common *ivdb)
{
	struct ivrs_ivmd *ivmd = (struct ivrs_ivmd *)ivdb;
	struct ivmd_flags flags;

	printf("Device ID:         0x%4.4x\n", ivmd->devid);
	printf("Auxilary Data:     0x%4.4x\n", ivmd->aux_data);
	printf("Reserved:          0x%lx\n", ivmd->reserved);
	printf("Start Address:     0x%lx\n", ivmd->start_addr);
	printf("Mem Block Length:  0x%lx\n", ivmd->mem_block_length);

	printf("IVMD Type Specific:\n");
	switch (ivmd->ivdb.type) {
	case IVMD_TYPE_ALL_PERIPHERALS:
		printf("  IVMD Type All Peripherals\n");
		printf("  Device ID Reserved\n");
		printf("  Auxiliary Data Reserved\n");
		break;
	case IVMD_TYPE_SPECIFIED_PERIPHERAL:
		printf("  IVMD Type Specified Peripherals\n");
		printf("  Specified Device ID\n");
		printf("  Auxiliary Data Reserved\n");
		break;
	case IVMD_TYPE_PERIPHERAL_RANGE:
		printf("  IVMD Type Peripheral Range\n");
		printf("  Starting Device ID of Range\n");
		printf("  Auxiliary Data Ending Device ID of Range\n");
	};

	flags.val = ivdb->flags;
	printf("  IVMD Flags\n");
	printf("  ---------------------------------\n");
	printf("    Unity:            0x%1.1x\n", flags.unity);
	printf("    IR:               0x%1.1x\n", flags.ir);
	printf("    IW:               0x%1.1x\n", flags.iw);
	printf("    Exclusion Range:  0x%1.1x\n", flags.excl_range);
	printf("    Reserved:         0x%1.1x\n", flags.reserved);
	printf("  ---------------------------------\n");
}

static void
acpi_parse_ivrs(struct acpi_table_header *table)
{
	struct acpi_table_ivrs *ivrs;
	struct ivrs_ivinfo info;
	struct ivrs_ivdb_common *ivdb;
	uint8_t *p;
	int i = 1, j = 1, k = 1;

	ivrs = (struct acpi_table_ivrs *)table;

	printf("I/O Virtualization Reporting Structure\n");
	printf("==================================================\n");
	printf("Signature:        %.4s\n", ivrs->header.signature);
	printf("Length:           0x%8.8x\n", ivrs->header.length);
	printf("Revision:         0x%2.2x\n", ivrs->header.revision);
	printf("Checksum:         0x%2.2x\n", ivrs->header.checksum);
	printf("OEMID:            %.*s\n", ACPI_OEM_ID_SIZE, ivrs->header.oem_id);
	printf("OEM Table ID:     %.*s\n", ACPI_OEM_TABLE_ID_SIZE, ivrs->header.oem_table_id);
	printf("OEM Revision:     0x%8.8x\n", ivrs->header.oem_revision);
	printf("Creator ID:       %.*s\n", ACPI_NAME_SIZE, ivrs->header.asl_compiler_id);
	printf("Creator Revision: 0x%8.8x\n", ivrs->header.asl_compiler_revision);
	printf("IVInfo:           0x%8.8x\n", ivrs->ivinfo);

	p = &ivrs->reserved[0];
	printf("Reserved[10]: %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x\n",
	  p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);

	info.val = ivrs->ivinfo;
	printf("  IVRS Info Field\n");
	printf("  ------------------------------------------------\n");
	printf("   EFRSup:          0x%1.1x\n", info.efr_sup);
	printf("   DMA Remap Sup:   0x%1.1x\n", info.dma_remap_sup);
	printf("   Reserved:        0x%1.1x\n", info.reserved1);
	printf("   GVA Size:        0x%1.1x\n", info.gva_size);
	printf("   PA Size:         0x%2.2x\n", info.pa_size);
	printf("   VA Size:         0x%2.2x\n", info.va_size);
	printf("   HtAtsResv:       0x%1.1x\n", info.ht_ats_resv);
	printf("   Reserved:        0x%3.3x\n", info.reserved2);
	printf("  ------------------------------------------------\n");

	ivdb = (struct ivrs_ivdb_common *)(ivrs + 1);

	printf("\nIVDB Structures...\n\n");

	while ( ((unsigned long)ivdb) <
		(((unsigned long)ivrs) + table->length) ) {
		switch (ivdb->type) {
		case IVHD_TYPE_10H:
		case IVHD_TYPE_11H:
		case IVHD_TYPE_40H:
			printf("I/O Virtualization Hardware Definition (IVHD) Structure #%d\n", i++);
			printf("-----------------------------------------------------------\n");
			printf("Type:                 0x%2.2x\n", ivdb->type);
			printf("Flags:                0x%2.2x\n", ivdb->flags);
			printf("Length:               0x%4.4x\n", ivdb->length);
			acpi_parse_one_ivhd(ivdb);
			printf("\n");
			break;
		case IVMD_TYPE_ALL_PERIPHERALS:
		case IVMD_TYPE_SPECIFIED_PERIPHERAL:
		case IVMD_TYPE_PERIPHERAL_RANGE:
			printf("I/O Virtualization Memory Definition (IVMD) Structure #%d\n", j++);
			printf("---------------------------------------------------------\n");
			printf("Type:           0x%2.2x\n", ivdb->type);
			printf("Flags:          0x%2.2x\n", ivdb->flags);
			printf("Length:         0x%4.4x\n", ivdb->length);
			acpi_parse_one_ivmd(ivdb);
			printf("\n");
			break;
		default:
			printf("Unknown Reporting Structure #%d\n", k++);
			printf("-------------------------------\n");
			printf("Type:           0x%2.2x\n", ivdb->type);
			printf("Flags:          0x%2.2x\n", ivdb->flags);
			printf("Length:         0x%4.4x\n", ivdb->length);
			printf("\n");
			break;
		}

		ivdb = ((void *)ivdb + ivdb->length);

	}

	printf("==================================================\n");
	printf("End IVRS\n");
}

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

	acpi_parse_ivrs(table);

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

	acpi_parse_ivrs(table);

done:
	if (table != NULL)
		free(table);
	if (infile != NULL)
		fclose(infile);
}
