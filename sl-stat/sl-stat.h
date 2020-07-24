/*
 * sl-stat.h: Constants and structures for sl-stat.c
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
#ifndef __SL_STAT_H__
#define __SL_STAT_H__

#define TXT_PUB_CONFIG_REGS_BASE 0xfed30000
#define TXT_PRIV_CONFIG_REGS_BASE 0xfed20000
#define TXT_CONFIG_REGS_SIZE (TXT_PUB_CONFIG_REGS_BASE - \
				 TXT_PRIV_CONFIG_REGS_BASE)
#define TXTCR_STS 0x0000
#define TXTCR_ESTS 0x0008
#define TXTCR_ERRORCODE 0x0030
#define TXTCR_VER_FSBIF 0x0100
#define TXTCR_DIDVID 0x0110
#define TXTCR_VER_QPIIF 0x0200
#define TXTCR_SINIT_BASE 0x0270
#define TXTCR_SINIT_SIZE 0x0278
#define TXTCR_HEAP_BASE 0x0300
#define TXTCR_HEAP_SIZE 0x0308
#define TXTCR_DPR 0x330
#define TXTCR_PUBLIC_KEY 0x0400
#define TXTCR_E2STS 0x08f0

#define HEAP_EXTDATA_TYPE_END 0
#define HEAP_EXTDATA_TYPE_BIOS_SPEC_VER 1
#define HEAP_EXTDATA_TYPE_ACM 2
#define HEAP_EXTDATA_TYPE_CUSTOM 4
#define HEAP_EXTDATA_TYPE_TPM_EVENT_LOG_PTR 5
#define HEAP_EXTDATA_TYPE_TPM_EVENT_LOG_PTR_2 7
#define HEAP_EXTDATA_TYPE_TPM_EVENT_LOG_PTR_2_1 8
#define TB_HALG_SHA1_LG 0x0000
#define TB_HALG_SHA1 0x0004
#define TB_HALG_SHA256 0x000B
#define TB_HALG_SM3 0x0012
#define TB_HALG_SHA384 0x000C
#define TB_HALG_SHA512 0x000D
#define SHA1_LENGTH 20
#define SHA256_LENGTH 32
#define SM3_LENGTH 32
#define SHA384_LENGTH 48
#define SHA512_LENGTH 64

#define PACKED __attribute__((packed))

typedef struct PACKED {
	uint32_t level;
	uint32_t facility;
	char type[];
	/* char msg[] */
} bootloader_log_msg_t;

typedef struct PACKED {
	uint32_t version;
	uint32_t producer;
	uint32_t size;
	uint32_t next_off;
	bootloader_log_msg_t msgs[];
} bootloader_log_t;

typedef void txt_heap_t;

typedef union {
	uint64_t _raw;
	struct {
		uint64_t senter_done_sts : 1;
		uint64_t sexit_done_sts : 1;
		uint64_t reserved1 : 4;
		uint64_t mem_config_lock_sts : 1;
		uint64_t private_open_sts : 1;
		uint64_t reserved2 : 7;
		uint64_t locality_1_open_sts : 1;
		uint64_t locality_2_open_sts : 1;
	};
} txt_sts_t;

typedef union {
	uint64_t _raw;
	struct {
		uint64_t txt_reset_sts : 1;
	};
} txt_ests_t;

typedef union {
	uint64_t _raw;
	struct {
		uint64_t reserved : 1;
		uint64_t secrets_sts : 1;
	};
} txt_e2sts_t;

typedef union {
	uint64_t _raw;
	struct {
		uint16_t vendor_id;
		uint16_t device_id;
		uint16_t revision_id;
		uint16_t reserved;
	};
} txt_didvid_t;

typedef union {
	uint64_t _raw;
	struct {
		uint64_t lock : 1;
		uint64_t reserved1 : 3;
		uint64_t top : 8;
		uint64_t reserved2 : 8;
		uint64_t size : 12;
		uint64_t reserved3 : 32; 
	};
} txt_dpr_t;

typedef struct PACKED {
	uint32_t type;
	uint32_t size;
	uint8_t data[];
} heap_ext_data_element_t;

typedef struct PACKED {
	uint32_t version;
	uint32_t bios_sinit_size;
	uint64_t lcp_pd_base;
	uint64_t lcp_pd_size;
	uint32_t num_logical_procs;
	uint64_t flags;
	heap_ext_data_element_t ext_data_elts[];
} bios_data_t;

typedef struct PACKED {
	uint16_t spec_ver_major;
	uint16_t spec_ver_minor;
	uint16_t spec_ver_rev;
} heap_bios_spec_ver_elt_t;

typedef struct PACKED {
	uint32_t num_acms;
	uint64_t acm_addrs[];
} heap_acm_elt_t;

typedef struct PACKED {
	uint32_t data1;
	uint16_t data2;
	uint16_t data3;
	uint16_t data4;
	uint8_t data5[];
} uuid_t;

typedef struct PACKED {
	uuid_t uuid;
	uint8_t data[];
} heap_custom_elt_t;

typedef struct PACKED {
	uint64_t event_log_phys_addr;
} heap_event_log_ptr_elt_t;

typedef uint8_t sha1_hash_t[SHA1_LENGTH];

typedef union {
	uint8_t sha1[SHA1_LENGTH];
	uint8_t sha256[SHA256_LENGTH];
	uint8_t sm3[SM3_LENGTH];
	uint8_t sha384[SHA384_LENGTH];
	uint8_t sha512[SHA512_LENGTH];
} tb_hash_t;

typedef struct PACKED {
	uint32_t pcr_index;
	uint32_t type;
	sha1_hash_t digest;
	uint32_t data_size;
	uint8_t data[];
} tpm12_pcr_event_t;

typedef struct PACKED {
	uint8_t signature[16];
	uint32_t revision;
	uint32_t digest_id;
	uint32_t digest_size;
} tpm20_log_descr_t;

typedef struct PACKED {
	uint8_t signature[20];
	uint8_t reserved[12];
	uint8_t container_ver_major;
	uint8_t container_ver_minor;
	uint8_t pcr_event_ver_major;
	uint8_t pcr_event_ver_minor;
	uint32_t size;
	uint32_t pcr_events_offset;
	uint32_t next_event_offset;
	tpm12_pcr_event_t pcr_events[];
} event_log_container_t;

typedef struct PACKED {
	uint16_t alg;
	uint16_t reserved;
	uint64_t phys_addr;
	uint32_t size;
	uint32_t pcr_events_offset;
	uint32_t next_event_offset;
} heap_event_log_descr_t;

typedef struct PACKED {
	uint32_t count;
	heap_event_log_descr_t event_log_descr[];
} heap_event_log_ptr_elt2_t;

typedef struct PACKED {
	uint64_t phys_addr;
	uint32_t allcoated_event_container_size;
	uint32_t first_record_offset;
	uint32_t next_record_offset;
} heap_event_log_ptr_elt2_1_t;

typedef struct PACKED{
	uint32_t pcr_index;
	uint32_t event_type;
	uint8_t digest[20];
	uint32_t event_data_size;
	uint8_t event_data[];
} tcg_pcr_event;

typedef struct PACKED {
	uint16_t algorithm_id;
	uint16_t digest_size;
} tcg_efi_spec_id_event_algorithm_size;

typedef struct PACKED {
	uint8_t signature[16];
	uint32_t platform_class;
	uint8_t spec_version_minor;
	uint8_t spec_version_major;
	uint8_t spec_errata;
	uint8_t uintn_size;
	uint32_t number_of_algorithms;
	tcg_efi_spec_id_event_algorithm_size digestSizes[5];
	uint8_t vendor_info_size;
	uint8_t vendor_info[];
} tcg_efi_specid_event_strcut;

typedef struct {
	uint64_t hash_alg;
	uint8_t digest[];
} TPMT_HA_1;

typedef struct {
	uint32_t count;
	TPMT_HA_1 digests[5];
} TPML_DIGEST_VALUES_1;

typedef struct PACKED {
	uint32_t pcr_index;
	uint32_t event_type;
	TPML_DIGEST_VALUES_1 digest;
	uint32_t event_size;
	uint8_t event[];
} tcg_pcr_event2;

#endif
