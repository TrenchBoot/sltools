/*
 * sl-stat: Linux app that can display register, heap, bootloader log,
 *          snd slaunch information.
 *
 * Copyright (c) 2020, Oracle and/or its affiliates.
 *
 * Copyright (c) 2006-2011, Intel Corporation
 * All rights reserved.
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
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <ctype.h>
#include <errno.h>
#include "sl-stat.h"

static bootloader_log_t *log;

/* Functions for printing bootloader_log */
static void read_log_file(char *filename)
{
	uint32_t log_fd;
	uint32_t file_size;
	ssize_t bytes_read;
	ssize_t offset = 0;
	bootloader_log_t *log_offset;

	log_fd = open(filename, O_RDONLY);

	if (errno)
		return;

	file_size = lseek(log_fd, 0, SEEK_END);
	lseek(log_fd, 0, SEEK_SET);

	log = malloc(file_size);

	do {
		log_offset = (bootloader_log_t *)((uint8_t *)log + offset);
		bytes_read = read(log_fd, log_offset, file_size);

		if (errno) {
			fprintf(stderr, "Error reading %s: %s\n", filename, strerror(errno));
			break;
		}

		offset += bytes_read;
	} while (bytes_read != 0);

	close(log_fd);

	if (errno)
		fprintf(stderr, "Error closing %s: %s\n", filename, strerror(errno));
}

static void print_bootloader_log(void)
{
	uint32_t offset;
	uint32_t type_len;
	uint32_t msg_len;
	bootloader_log_msg_t *msgs;

	if (log == NULL)
		return;

	offset = sizeof(*log);

	while (offset < log->next_off) {
		msgs = (bootloader_log_msg_t *) ((uint8_t *) log + offset);

		printf("%s", msgs->type);
		type_len = strlen(msgs->type) + 1;

		printf("%s", msgs->type + type_len);
		msg_len = strlen(msgs->type + type_len) + 1;

		offset += sizeof(*msgs) + type_len + msg_len;
	}
	printf("\n");
}

/* Functions for printing the registers/heap */
static inline const char * bit_to_str(uint64_t b)
{
	return b ? "TRUE" : "FALSE";
}

static inline uint64_t read_txt_config_reg(void *config_regs_base, uint32_t reg)
{
	/* these are MMIO so make sure compiler doesn't optimize */
	return *(volatile uint64_t *)(config_regs_base + reg);
}

static void print_hex(const char* prefix, const void *start, size_t len)
{
	int i;
	const void *end = start + len;
	while (start < end) {
		printf("%s", prefix);
		for (i = 0; i < 16; i++) {
			if (start < end)
				printf("%02x ", *(uint8_t *)start);
			start++;
		}
		printf("\n");
	}
}

static void display_config_regs(void *txt_config_base)
{
	txt_sts_t sts;
	txt_ests_t ests;
	txt_e2sts_t e2sts;
	txt_didvid_t didvid;
	uint64_t fsbif;
	uint64_t qpiif;
	txt_dpr_t dpr;
	uint8_t key[256/8];
	unsigned int i = 0;

	printf("Intel(r) TXT Configuration Registers:\n");

	/* STS */
	sts._raw = read_txt_config_reg(txt_config_base, TXTCR_STS);
	printf("\tSTS: 0x%08jx\n", sts._raw);
	printf("\t    senter_done: %s\n", bit_to_str(sts.senter_done_sts));
	printf("\t    sexit_done: %s\n", bit_to_str(sts.sexit_done_sts));
	printf("\t    mem_config_lock: %s\n", bit_to_str(sts.mem_config_lock_sts));
	printf("\t    private_open: %s\n", bit_to_str(sts.private_open_sts));
	printf("\t    locality_1_open: %s\n", bit_to_str(sts.locality_1_open_sts));
	printf("\t    locality_2_open: %s\n", bit_to_str(sts.locality_2_open_sts));

	/* ESTS */
	ests._raw = read_txt_config_reg(txt_config_base, TXTCR_ESTS);
	printf("\tESTS: 0x%02jx\n", ests._raw);
	printf("\t    txt_reset: %s\n", bit_to_str(ests.txt_reset_sts));

	/* E2STS */
	e2sts._raw = read_txt_config_reg(txt_config_base, TXTCR_E2STS);
	printf("\tE2STS: 0x%016jx\n", e2sts._raw);
	printf("\t    secrets: %s\n", bit_to_str(e2sts.secrets_sts));

	/* ERRORCODE */
	printf("\tERRORCODE: 0x%08jx\n", read_txt_config_reg(txt_config_base,
							 TXTCR_ERRORCODE));

	/* DIDVID */
	didvid._raw = read_txt_config_reg(txt_config_base, TXTCR_DIDVID);
	printf("\tDIDVID: 0x%016jx\n", didvid._raw);
	printf("\t    vendor_id: 0x%x\n", didvid.vendor_id);
	printf("\t    device_id: 0x%x\n", didvid.device_id);
	printf("\t    revision_id: 0x%x\n", didvid.revision_id);

	/* FSBIF */
	fsbif = read_txt_config_reg(txt_config_base, TXTCR_VER_FSBIF);
	printf("\tFSBIF: 0x%016jx\n", fsbif);

	/* QPIIF */
	qpiif = read_txt_config_reg(txt_config_base, TXTCR_VER_QPIIF);
	printf("\tQPIIF: 0x%016jx\n", qpiif);

	/* SINIT.BASE/SIZE */
	printf("\tSINIT.BASE: 0x%08jx\n", read_txt_config_reg(txt_config_base,
							TXTCR_SINIT_BASE));
	printf("\tSINIT.SIZE: %juB (0x%jx)\n",
		read_txt_config_reg(txt_config_base, TXTCR_SINIT_SIZE),
		read_txt_config_reg(txt_config_base, TXTCR_SINIT_SIZE));

	/* HEAP.BASE/SIZE */
	printf("\tHEAP.BASE: 0x%08jx\n", read_txt_config_reg(txt_config_base,
							TXTCR_HEAP_BASE));
	printf("\tHEAP.SIZE: %juB (0x%jx)\n",
		read_txt_config_reg(txt_config_base, TXTCR_HEAP_SIZE),
		read_txt_config_reg(txt_config_base, TXTCR_HEAP_SIZE));

	/* DPR.BASE/SIZE */
	dpr._raw = read_txt_config_reg(txt_config_base, TXTCR_DPR);
	printf("\tDPR: 0x%016jx\n", dpr._raw);
	printf("\t    lock: %s\n", bit_to_str(dpr.lock));
	printf("\t    top: 0x%08x\n", (uint32_t)dpr.top << 20);
	printf("\t    size: %uMB (%uB)\n", dpr.size, dpr.size*1024*1024);

	/* PUBLIC.KEY */
	do {
		*(uint64_t *)&key[i] = read_txt_config_reg(txt_config_base,
							TXTCR_PUBLIC_KEY + i);
		i += sizeof(uint64_t);
	} while (i < sizeof(key));
	printf("\tPUBLIC.KEY:\n");
	print_hex("\t    ", key, sizeof(key)); printf("\n");

	/* easy-to-see status of TXT and secrets */
	printf("***********************************************************\n");
	printf("\t TXT measured launch: %s\n", bit_to_str(sts.senter_done_sts));
	printf("\t secrets flag set: %s\n", bit_to_str(e2sts.secrets_sts));
	printf("***********************************************************\n");
}

static void print_bios_spec_ver_elt(const heap_ext_data_element_t *elt)
{
	const heap_bios_spec_ver_elt_t *bios_spec_ver_elt =
		(const heap_bios_spec_ver_elt_t *)elt->data;

	printf("\t\t BIOS_SPEC_VER:\n");
	printf("\t\t     major: 0x%x\n", bios_spec_ver_elt->spec_ver_major);
	printf("\t\t     minor: 0x%x\n", bios_spec_ver_elt->spec_ver_minor);
	printf("\t\t     rev: 0x%x\n", bios_spec_ver_elt->spec_ver_rev);
}

static void print_acm_elt(const heap_ext_data_element_t *elt)
{
	const heap_acm_elt_t *acm_elt = (const heap_acm_elt_t *)elt->data;
	unsigned int i;

	printf("\t\t ACM:\n");
	printf("\t\t     num_acms: %u\n", acm_elt->num_acms);
	for (i = 0; i < acm_elt->num_acms; i++)
		printf("\t\t     acm_addrs[%u]: 0x%jx\n", i, acm_elt->acm_addrs[i]);
}

static inline void print_uuid(const uuid_t *uuid)
{
	printf("{0x%08x, 0x%04x, 0x%04x, 0x%04x, \n"
		"\t\t{0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x}}",
		uuid->data1, (uint32_t)uuid->data2, (uint32_t)uuid->data3,
		(uint32_t)uuid->data4, (uint32_t)uuid->data5[0],
		(uint32_t)uuid->data5[1], (uint32_t)uuid->data5[2],
		(uint32_t)uuid->data5[3], (uint32_t)uuid->data5[4],
		(uint32_t)uuid->data5[5]);
}

static void print_custom_elt(const heap_ext_data_element_t *elt)
{
	const heap_custom_elt_t *custom_elt = (const heap_custom_elt_t *)elt->data;

	printf("\t\t CUSTOM:\n");
	printf("\t\t     size: %u\n", elt->size);
	printf("\t\t     uuid: "); print_uuid(&custom_elt->uuid);
	printf("\n");
}

static inline unsigned int get_hash_size(uint16_t hash_alg)
{
	if (hash_alg == TB_HALG_SHA1 || hash_alg == TB_HALG_SHA1_LG)
		return SHA1_LENGTH;
	else if (hash_alg == TB_HALG_SHA256)
		return SHA256_LENGTH;
	else if (hash_alg == TB_HALG_SM3)
		return SM3_LENGTH;
	else if (hash_alg == TB_HALG_SHA384)
		return SHA384_LENGTH;
	else if (hash_alg == TB_HALG_SHA512)
		return SHA512_LENGTH;
	else
		return 0;
}

static void print_hash(const tb_hash_t *hash, uint16_t hash_alg)
{
	if (hash == NULL) {
		printf("NULL");
		return;
	}

	if (hash_alg == TB_HALG_SHA1)
		print_hex(NULL, (uint8_t *)hash->sha1, sizeof(hash->sha1));
	else if (hash_alg == TB_HALG_SHA256)
		print_hex(NULL, (uint8_t *)hash->sha256, sizeof(hash->sha256));
	else if (hash_alg == TB_HALG_SM3)
		print_hex(NULL, (uint8_t *)hash->sm3, sizeof(hash->sm3));
	else if (hash_alg == TB_HALG_SHA384)
		print_hex(NULL, (uint8_t *)hash->sha384, sizeof(hash->sha384));
	else {
		printf("unsupported hash alg (%u)\n", hash_alg);
		return;
	}
}

static inline void print_heap_hash(const sha1_hash_t hash)
{
	print_hash((const tb_hash_t *)hash, TB_HALG_SHA1);
}

static void print_event(const tpm12_pcr_event_t *evt)
{
	printf("\t\t\t Event:\n");
	printf("\t\t\t     PCRIndex: %u\n", evt->pcr_index);
	printf("\t\t\t         Type: 0x%x\n", evt->type);
	printf("\t\t\t       Digest: ");
	print_heap_hash(evt->digest);
	printf("\t\t\t         Data: %u bytes", evt->data_size);
	print_hex("\t\t\t         ", evt->data, evt->data_size);
}

static void print_evt_log(const event_log_container_t *elog)
{
	const tpm12_pcr_event_t *curr, *next;

	printf("\t\t\t Event Log Container:\n");
	printf("\t\t\t     Signature: %s\n", elog->signature);
	printf("\t\t\t  ContainerVer: %u.%u\n",
		elog->container_ver_major, elog->container_ver_minor);
	printf("\t\t\t   PCREventVer: %u.%u\n",
		elog->pcr_event_ver_major, elog->pcr_event_ver_minor);
	printf("\t\t\t          Size: %u\n", elog->size);
	printf("\t\t\t  EventsOffset: [%u,%u]\n",
		elog->pcr_events_offset, elog->next_event_offset);

	curr = (tpm12_pcr_event_t *)((void*)elog + elog->pcr_events_offset);
	next = (tpm12_pcr_event_t *)((void*)elog + elog->next_event_offset);

	while (curr < next) {
		print_event(curr);
		curr = (void *)curr + sizeof(*curr) + curr->data_size;
	}
}

static void print_evt_log_ptr_elt(const heap_ext_data_element_t *elt)
{
	const heap_event_log_ptr_elt_t *elog_elt =
		(const heap_event_log_ptr_elt_t *)elt->data;

	printf("\t\t EVENT_LOG_POINTER:\n");
	printf("\t\t       size: %u\n", elt->size);
	printf("\t\t  elog_addr: 0x%jx\n", elog_elt->event_log_phys_addr);

	if (elog_elt->event_log_phys_addr)
		print_evt_log((event_log_container_t *)(unsigned long)
			elog_elt->event_log_phys_addr);
}

static void print_event_2(void *evt, uint16_t alg)
{
	uint32_t hash_size, data_size; 
	void *next = evt;

	hash_size = get_hash_size(alg); 
	if (hash_size == 0)
		return;

	printf("\t\t\t Event:\n");
	printf("\t\t\t     PCRIndex: %u\n", *((uint32_t *)next));
    
	if (*((uint32_t *)next) > 24 && *((uint32_t *)next) != 0xFF) {
		printf("\t\t\t           Wrong Event Log.\n");
		return;
	}
    
	next += sizeof(uint32_t);
	printf("\t\t\t         Type: 0x%x\n", *((uint32_t *)next));

	if (*((uint32_t *)next) > 0xFFF) {
		printf("\t\t\t           Wrong Event Log.\n");
		return;
	}

	next += sizeof(uint32_t);
	printf("\t\t\t       Digest: ");
	print_hex(NULL, (uint8_t *)next, hash_size);
	next += hash_size;
	data_size = *(uint32_t *)next;
	printf("\t\t\t         Data: %u bytes", data_size);
	if (data_size > 4096) {
		printf("\t\t\t           Wrong Event Log.\n");
		return;
	}

	next += sizeof(uint32_t);
	if (data_size)
		print_hex("\t\t\t         ", (uint8_t *)next, data_size);
	else
		printf("\n");
}

static void print_evt_log_ptr_elt_2(const heap_ext_data_element_t *elt)
{
	const heap_event_log_ptr_elt2_t *elog_elt =
		(const heap_event_log_ptr_elt2_t *)elt->data;
	const heap_event_log_descr_t *log_descr;
	unsigned int i;
	uint32_t hash_size, data_size; 
	void *curr, *next;

	printf("\t\t EVENT_LOG_PTR:\n");
	printf("\t\t       size: %u\n", elt->size);
	printf("\t\t      count: %d\n", elog_elt->count);

	for (i = 0; i<elog_elt->count; i++) {
		log_descr = &elog_elt->event_log_descr[i];
		printf("\t\t\t Log Descrption:\n");
		printf("\t\t\t             Alg: %u\n", log_descr->alg);
		printf("\t\t\t            Size: %u\n", log_descr->size);
		printf("\t\t\t    EventsOffset: [%u,%u]\n",
			log_descr->pcr_events_offset,
			log_descr->next_event_offset);

		if (log_descr->pcr_events_offset == log_descr->next_event_offset) {
			printf("\t\t\t              No Event Log.\n");
			continue;
		}

		hash_size = get_hash_size(log_descr->alg);
		if (hash_size == 0)
			return;

		curr = (void *)(unsigned long)log_descr->phys_addr +
			log_descr->pcr_events_offset;
		next = (void *)(unsigned long)log_descr->phys_addr +
			log_descr->next_event_offset;

		if (log_descr->alg != TB_HALG_SHA1){
			print_event_2(curr, TB_HALG_SHA1);
			curr += sizeof(tpm12_pcr_event_t) + sizeof(tpm20_log_descr_t);
		}

		while (curr < next) {
			print_event_2(curr, log_descr->alg);
			data_size = *(uint32_t *)(curr + 2*sizeof(uint32_t) + hash_size);
			curr += 3*sizeof(uint32_t) + hash_size + data_size;
		}
	}
}

static uint32_t print_event_2_1_log_header(void *evt)
{
	uint32_t i;
	tcg_pcr_event *evt_ptr = (tcg_pcr_event *)evt;
	tcg_efi_specid_event_strcut *evt_data_ptr = (tcg_efi_specid_event_strcut *) evt_ptr->event_data;

	printf("\t TCG Event Log Header:\n");
	printf("\t\t       pcr_index: %u\n", evt_ptr->pcr_index);
	printf("\t\t      event_type: %u\n", evt_ptr->event_type);
	printf("\t\t          digest: %s\n", evt_ptr->digest);
	printf("\t\t event_data_size: %u\n", evt_ptr->event_data_size);

	// print out event log header data

	printf("\t\t 	   header event data:  \n");
	printf("\t\t\t              signature: %s\n", evt_data_ptr->signature);
	printf("\t\t\t         platform_class: %u\n", evt_data_ptr->platform_class);
	printf("\t\t\t     spec_version_major: %u\n", evt_data_ptr->spec_version_major);
	printf("\t\t\t     spec_version_minor: %u\n", evt_data_ptr->spec_version_minor);
	printf("\t\t\t            spec_errata: %u\n", evt_data_ptr->spec_errata);
	printf("\t\t\t             uintn_size: %u\n", evt_data_ptr->uintn_size);
	printf("\t\t\t   number_of_algorithms: %u\n", evt_data_ptr->number_of_algorithms);

	for (i = 0; i < evt_data_ptr->number_of_algorithms; i++) {
		printf("\t\t\t\t   algorithm_id: 0x%x \n", evt_data_ptr->digestSizes[i].algorithm_id);
		printf("\t\t\t\t    digest_size: %u\n", evt_data_ptr->digestSizes[i].digest_size);
	}

	printf("\t\t\t       vendor_info: %u bytes\n", evt_data_ptr->vendor_info_size);
	print_hex(NULL, evt_data_ptr->vendor_info, evt_data_ptr->vendor_info_size);

	return evt_ptr->event_data_size;
}

static uint32_t print_event_2_1(void *evt)
{
	tcg_pcr_event2 *evt_ptr = (tcg_pcr_event2 *)evt;
	uint32_t i;
	uint8_t *evt_data_ptr;
	uint16_t hash_alg;
	uint32_t event_size = 0;

	printf("\t\t\t TCG Event:\n");
	printf("\t\t\t      pcr_index: %u\n", evt_ptr->pcr_index);
	printf("\t\t\t     event_type: 0x%x\n", evt_ptr->event_type);
	printf("\t\t\t          count: %u\n", evt_ptr->digest.count);
	if (evt_ptr->digest.count != 0) {
		evt_data_ptr = (uint8_t *)evt_ptr->digest.digests[0].digest;
		hash_alg = evt_ptr->digest.digests[0].hash_alg;
		for (i = 0; i < evt_ptr->digest.count; i++) {
			switch (hash_alg) {
				case TB_HALG_SHA1:
					printf("SHA1: \n");
					print_hex(NULL, evt_data_ptr, SHA1_LENGTH);
					evt_data_ptr += SHA1_LENGTH;
					break;
 
				case TB_HALG_SHA256:
					printf("SHA256: \n");
					print_hex(NULL, evt_data_ptr, SHA256_LENGTH);
					evt_data_ptr += SHA256_LENGTH;
					break;
 
				case TB_HALG_SM3:
					printf("SM3_256: \n");
					print_hex(NULL, evt_data_ptr, SM3_LENGTH);
					evt_data_ptr += SM3_LENGTH;
					break;
 
				case TB_HALG_SHA384:
					printf("SHA384: \n");
					print_hex(NULL, evt_data_ptr, SHA384_LENGTH);
					evt_data_ptr += SHA384_LENGTH;
					break;
 
				case TB_HALG_SHA512:
					printf("SHA512:  \n");
					print_hex(NULL, evt_data_ptr, SHA512_LENGTH);
					evt_data_ptr += SHA512_LENGTH;
					break;
				default:
					printf("Unsupported algorithm: %u\n", evt_ptr->digest.digests[i].hash_alg);
			}
			hash_alg = (uint16_t)*evt_data_ptr;
			evt_data_ptr += sizeof(uint16_t);
		}
		evt_data_ptr -= sizeof(uint16_t);
		event_size = (uint32_t)*evt_data_ptr;
		printf("\t\t\t     event_data: %u bytes", event_size);
		evt_data_ptr += sizeof(uint32_t);
		print_hex("\t\t\t     ", evt_data_ptr, event_size);
	}
	else {
		printf("sth wrong in TCG event log: algoritm count = %u\n", evt_ptr->digest.count);
		evt_data_ptr= (uint8_t *)evt +12;
	}
	return (evt_data_ptr + event_size - (uint8_t *)evt);
}

static void print_evt_log_ptr_elt_2_1(const heap_ext_data_element_t *elt)
{
	const heap_event_log_ptr_elt2_1_t *elog_elt = (const heap_event_log_ptr_elt2_1_t *)elt->data;
	void *curr, *next;
	uint32_t event_header_data_size;

	printf("\t TCG EVENT_LOG_PTR:\n");
	printf("\t\t       type: %d\n", elt->type);
	printf("\t\t       size: %u\n", elt->size);
	printf("\t TCG Event Log Descrption:\n");
	printf("\t     allcoated_event_container_size: %u\n", elog_elt->allcoated_event_container_size);
	printf("\t                       EventsOffset: [%u,%u]\n",
		elog_elt->first_record_offset, elog_elt->next_record_offset);

	if (elog_elt->first_record_offset == elog_elt->next_record_offset) {
		printf("\t\t\t No Event Log found.\n");
		return;
	}

	curr = (void *)(unsigned long)elog_elt->phys_addr + elog_elt->first_record_offset;
	next = (void *)(unsigned long)elog_elt->phys_addr + elog_elt->next_record_offset;
	event_header_data_size = print_event_2_1_log_header(curr);

	curr += sizeof(tcg_pcr_event) + event_header_data_size;
	while (curr < next) {
		curr += print_event_2_1(curr);
	}
}

static inline uint64_t get_bios_data_size(const txt_heap_t *heap)
{
	return *(uint64_t *)heap;
}

static inline bios_data_t *get_bios_data_start(const txt_heap_t *heap)
{
	return (bios_data_t *)((char *)heap + sizeof(uint64_t));
}

static void print_ext_data_elts(const heap_ext_data_element_t elts[])
{
	const heap_ext_data_element_t *elt = elts;

	printf("\t ext_data_elts[]:\n");
	while (elt->type != HEAP_EXTDATA_TYPE_END) {
		switch ( elt->type ) {
			case HEAP_EXTDATA_TYPE_BIOS_SPEC_VER:
				print_bios_spec_ver_elt(elt);
				break;
			case HEAP_EXTDATA_TYPE_ACM:
				print_acm_elt(elt);
				break;
			case HEAP_EXTDATA_TYPE_CUSTOM:
				print_custom_elt(elt);
				break;
			case HEAP_EXTDATA_TYPE_TPM_EVENT_LOG_PTR:
				print_evt_log_ptr_elt(elt);
				break;
			case HEAP_EXTDATA_TYPE_TPM_EVENT_LOG_PTR_2:
				print_evt_log_ptr_elt_2(elt);
				break;
			case HEAP_EXTDATA_TYPE_TPM_EVENT_LOG_PTR_2_1:
				print_evt_log_ptr_elt_2_1(elt);
				break;
			default:
				printf("\t\t unknown element:  type: %u, size: %u\n",
					elt->type, elt->size);
				break;
		}
		elt = (void *)elt + elt->size;
	}
}

static void print_bios_data(const bios_data_t *bios_data, uint64_t size)
{
	printf("bios_data (@%p, %jx):\n", bios_data,
		*((uint64_t *)bios_data - 1));
	printf("\t version: %u\n", bios_data->version);
	printf("\t bios_sinit_size: 0x%x (%u)\n", bios_data->bios_sinit_size,
		bios_data->bios_sinit_size);
	printf("\t lcp_pd_base: 0x%jx\n", bios_data->lcp_pd_base);
	printf("\t lcp_pd_size: 0x%jx (%ju)\n", bios_data->lcp_pd_size,
		bios_data->lcp_pd_size);
	printf("\t num_logical_procs: %u\n", bios_data->num_logical_procs);
	if (bios_data->version >= 3)
		printf("\t flags: 0x%08jx\n", bios_data->flags);
	if (bios_data->version >= 4 && size > sizeof(*bios_data) + sizeof(size))
		print_ext_data_elts(bios_data->ext_data_elts);
}

static void display_heap(txt_heap_t *heap)
{
	uint64_t size = get_bios_data_size(heap);
	bios_data_t *bios_data = get_bios_data_start(heap);
	print_bios_data(bios_data, size);
}

static void print_help(const char *usage_str, const char *option_string[])
{
	uint16_t i = 0;
	if (usage_str == NULL || option_string == NULL)
		return;

	printf("\nUsage: %s\n", usage_str);

	for ( ; option_string[i] != NULL; i++ )
		printf("%s", option_string[i]);
}

static int print_regs(bool display_heap_optin)
{
	int fd_mem;
	uint64_t heap = 0;
	uint64_t heap_size = 0;
	void *buf = NULL;
	void *buf_config_regs_read;
	void *buf_config_regs_mmap;
	off_t seek_ret = -1;
	size_t read_ret = 0;

	fd_mem = open("/dev/mem", O_RDONLY);
	if (fd_mem == -1) {
		printf("ERROR: cannot open /dev/mem\n");
		return 1;
	}

	/*
	 * display public config regs
	 */
	seek_ret = lseek(fd_mem, TXT_PUB_CONFIG_REGS_BASE, SEEK_SET);
	if (seek_ret == -1)
		printf("ERROR: seeking public config registers failed: %s, try mmap\n",
			strerror(errno));
	else {
		buf = malloc(TXT_CONFIG_REGS_SIZE);
		if (buf == NULL)
			printf("ERROR: out of memory, try mmap\n");
		else {
			read_ret = read(fd_mem, buf, TXT_CONFIG_REGS_SIZE);
			if (read_ret != TXT_CONFIG_REGS_SIZE) {
				printf("ERROR: reading public config registers failed: %s,"
					"try mmap\n", strerror(errno));
				free(buf);
				buf = NULL;
			}
			else
				buf_config_regs_read = buf;
		}
	}

	/*
	 * try mmap to display public config regs,
	 * since public config regs should be displayed always.
	 */
	if (buf == NULL) {
		buf = mmap(NULL, TXT_CONFIG_REGS_SIZE, PROT_READ,
			MAP_PRIVATE, fd_mem, TXT_PUB_CONFIG_REGS_BASE);
		if (buf == MAP_FAILED) {
			printf("ERROR: cannot map config regs by mmap()\n");
			buf = NULL;
		}
		else
			buf_config_regs_mmap = buf;
	}

	if (buf) {
		display_config_regs(buf);
		heap = read_txt_config_reg(buf, TXTCR_HEAP_BASE);
		heap_size = read_txt_config_reg(buf, TXTCR_HEAP_SIZE);
	}

	/*
	 * display heap
	 */
	if (heap && heap_size && display_heap_optin) {
		seek_ret = lseek(fd_mem, heap, SEEK_SET);
		if (seek_ret == -1) {
			printf("ERROR: seeking TXT heap failed by lseek(): %s, try mmap\n",
				strerror(errno));
			goto try_mmap_heap;
		}
		buf = malloc(heap_size);
		if (buf == NULL) {
			printf("ERROR: out of memory, try mmap\n");
			goto try_mmap_heap;
		}
		read_ret = read(fd_mem, buf, heap_size);
		if (read_ret != heap_size) {
			printf("ERROR: reading TXT heap failed by read(): %s, try mmap\n",
				strerror(errno));
			free(buf);
			goto try_mmap_heap;
		}
		display_heap((txt_heap_t *)buf);
		free(buf);
		goto try_display_log;

	try_mmap_heap:

		buf = mmap(NULL, heap_size, PROT_READ, MAP_PRIVATE, fd_mem, heap);
		if (buf == MAP_FAILED)
			printf("ERROR: cannot map TXT heap by mmap()\n");
		else {
			display_heap((txt_heap_t *)buf);
			munmap(buf, heap_size);
		}
	}

try_display_log:
	if (buf_config_regs_read)
		free(buf_config_regs_read);
	if (buf_config_regs_mmap)
		munmap(buf_config_regs_mmap, TXT_CONFIG_REGS_SIZE);

	close(fd_mem);

	return 0;
}

/* Functions for printing kmsg */
static char *parse_kmsg(char *buf, struct timeval *tv)
{
	char *buf_index = buf;
	const char *buf_end;
	char *msg;
	char *time_str;
	uint64_t time_uint;

	buf_end = buf + strlen(buf) - 1;

	while (buf_index < buf_end && isspace(*buf_index))
		buf_index++;

	/* Skip facility */
	strtok(buf_index, ",");

	/* Skip Sequence */
	strtok(NULL, ",;");

	time_str = strtok(NULL, ",;");
	time_uint = strtoumax(time_str, NULL, 10);
	tv->tv_sec = time_uint / 1000000;
	tv->tv_usec = time_uint % 1000000;

	strtok(NULL, ";");

	msg = strtok(NULL, "\n");
	return msg;
}

static int is_slaunch(char *msg)
{
	if (strncmp(msg, "slaunch", 7) == 0)
		return 1;
	return 0;
}

static void print_kmsg(void)
{
	uint32_t kmsg_fd;
	ssize_t read_size;
	struct timeval tv;
	char buf[BUFSIZ];
	char *msg;

	kmsg_fd = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);

	if (kmsg_fd < 0)
		return;

	tv.tv_sec = 0;
	tv.tv_usec = 0;

	do {
		read_size = read(kmsg_fd, buf, BUFSIZ);
		if (read_size > 0) {
			msg = parse_kmsg(buf, &tv);
			if (is_slaunch(msg))
				printf("[%5ld.%06ld] %s\n", tv.tv_sec, tv.tv_usec, msg);
		}
	} while (read_size > 0);

	close(kmsg_fd);
}

static const char *short_option = "f:hp";
static struct option longopts[] = {
	{"file", 1, 0, 'f'},
	{"heap", 0, 0, 'p'},
	{"help", 0, 0, 'h'},
	{0, 0, 0, 0}
};
static const char *usage_string = "sl-stat [-p|--heap] [-h|--help] [-f|--file]";
static const char *option_strings[] = {
	"-f, --file\tprint log from a file.\n",
	"-p --heap:\t\tprint out heap info.\n",
	"-h, --help:\tprint out this help message.\n",
	NULL
};

int main(int argc, char *argv[])
{
	char *filename = "/sys/kernel/boot_params/bootloader_log";
	bool display_heap_optin = false;
	int c;
	while ((c = getopt_long(argc, (char **const)argv, short_option,
		longopts, NULL)) != -1) {
		switch (c) {
		case 'f':
			filename = optarg;
			break;
		case 'h':
			print_help(usage_string, option_strings);
			return 0;

		case 'p':
			display_heap_optin = true;
			break;

		default:
			return 1;
		}
	}

	read_log_file(filename);
	print_regs(display_heap_optin);
	print_bootloader_log();
	print_kmsg();

	return 0;
}
