//
// acl.cpp
// ~~~~~~~
//
// Copyright (c) 2019 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include "utils/acl.hpp"

#define	LPM_MAX_PREFIX		(128)
#define	LPM_MAX_WORDS		(LPM_MAX_PREFIX >> 5)
#define	LPM_TO_WORDS(x)		((x) >> 2)
#define	LPM_HASH_STEP		(8)
#define	LPM_LEN_IDX(len)	((len) >> 4)

namespace acl_util {

	typedef struct lpm_ent {
		struct lpm_ent* next;
		void* val;
		unsigned	len;
		uint8_t		key[1];
	} lpm_ent_t;

	typedef struct {
		unsigned	hashsize;
		unsigned	nitems;
		lpm_ent_t** bucket;
	} lpm_hmap_t;

	struct lpm {
		uint32_t	bitmask[LPM_MAX_WORDS];
		void* defvals[2];
		lpm_hmap_t	prefix[LPM_MAX_PREFIX + 1];
	};

	static const uint32_t zero_address[LPM_MAX_WORDS] = {0};
	typedef void (*lpm_dtor_t)(void*, const void*, size_t, void*);

	template <typename Integral>
	static inline unsigned ffs_template(Integral x) {
		if (x == 0) return 0u;
		unsigned r = 1;
		while ((x & 1) == 0)
			x >>= 1, ++r;
		return r;
	}

	/*
	 * fnv1a_hash: Fowler-Noll-Vo hash function (FNV-1a variant).
	 */
	static uint32_t
		fnv1a_hash(const void* buf, size_t len)
	{
		uint32_t hash = 2166136261UL;
		const uint8_t* p = (const uint8_t*)buf;

		while (len--) {
			hash ^= *p++;
			hash *= 16777619U;
		}
		return hash;
	}


	/*
	 * compute_prefix: given the address and prefix length, compute and
	 * return the address prefix.
	 */
	static inline void compute_prefix(const unsigned nwords,
		const uint32_t* addr, unsigned preflen, uint32_t* prefix)
	{
		uint32_t addr2[4];

		if ((uintptr_t)addr & 3) {
			/* Unaligned address: just copy for now. */
			memcpy(addr2, addr, nwords * 4);
			addr = addr2;
		}
		for (unsigned i = 0; i < nwords; i++) {
			if (preflen == 0) {
				prefix[i] = 0;
				continue;
			}
			if (preflen < 32) {
				uint32_t mask = htonl(0xffffffff << (32 - preflen));
				prefix[i] = addr[i] & mask;
				preflen = 0;
			}
			else {
				prefix[i] = addr[i];
				preflen -= 32;
			}
		}
	}

	static bool
	hashmap_rehash(lpm_hmap_t* hmap, unsigned size)
	{
		lpm_ent_t** bucket;
		unsigned hashsize;

		for (hashsize = 1; hashsize < size; hashsize <<= 1) {
			continue;
		}
		if ((bucket = (lpm_ent_t**)calloc(1, hashsize * sizeof(lpm_ent_t*))) == NULL) {
			return false;
		}
		for (unsigned n = 0; n < hmap->hashsize; n++) {
			lpm_ent_t* list = hmap->bucket[n];

			while (list) {
				lpm_ent_t* entry = list;
				uint32_t hash = fnv1a_hash(entry->key, entry->len);
				const unsigned i = hash & (hashsize - 1);

				list = entry->next;
				entry->next = bucket[i];
				bucket[i] = entry;
			}
		}
		hmap->hashsize = hashsize;
		free(hmap->bucket); // may be NULL
		hmap->bucket = bucket;
		return true;
	}

	static lpm_ent_t* hashmap_insert(lpm_hmap_t* hmap, const void* key, const size_t len)
	{
		const unsigned target = hmap->nitems + LPM_HASH_STEP;
		const size_t entlen = offsetof(lpm_ent_t, key[len]);
		uint32_t hash, i;
		lpm_ent_t* entry;

		if (hmap->hashsize < target && !hashmap_rehash(hmap, target)) {
			return NULL;
		}

		hash = fnv1a_hash(key, len);
		i = hash & (hmap->hashsize - 1);
		entry = hmap->bucket[i];
		while (entry) {
			if (entry->len == len && memcmp(entry->key, key, len) == 0) {
				return entry;
			}
			entry = entry->next;
		}

		if ((entry = (lpm_ent_t*)malloc(entlen)) != NULL) {
			memcpy(entry->key, key, len);
			entry->next = hmap->bucket[i];
			entry->len = (unsigned)len;

			hmap->bucket[i] = entry;
			hmap->nitems++;
		}
		return entry;
	}

	static lpm_ent_t* hashmap_lookup(lpm_hmap_t* hmap, const void* key, size_t len)
	{
		const uint32_t hash = fnv1a_hash(key, len);
		const unsigned i = hash & (hmap->hashsize - 1);
		lpm_ent_t* entry;

		if (hmap->hashsize == 0) {
			return NULL;
		}
		entry = hmap->bucket[i];

		while (entry) {
			if (entry->len == len && memcmp(entry->key, key, len) == 0) {
				return entry;
			}
			entry = entry->next;
		}
		return NULL;
	}

	static int hashmap_remove(lpm_hmap_t* hmap, const void* key, size_t len)
	{
		const uint32_t hash = fnv1a_hash(key, len);
		const unsigned i = hash & (hmap->hashsize - 1);
		lpm_ent_t* prev = NULL, * entry;

		if (hmap->hashsize == 0) {
			return -1;
		}
		entry = hmap->bucket[i];

		while (entry) {
			if (entry->len == len && memcmp(entry->key, key, len) == 0) {
				if (prev) {
					prev->next = entry->next;
				}
				else {
					hmap->bucket[i] = entry->next;
				}
				free(entry);
				return 0;
			}
			prev = entry;
			entry = entry->next;
		}
		return -1;
	}

	/*
	 * lpm_remove: remove the specified prefix.
	 */
	int lpm_remove(lpm* p, const void* addr, size_t len, unsigned preflen)
	{
		const unsigned nwords = (unsigned)LPM_TO_WORDS(len);
		std::vector<uint32_t> prefix(nwords, 0);
		assert(len == 4 || len == 16);

		if (preflen == 0) {
			p->defvals[LPM_LEN_IDX(len)] = NULL;
			return 0;
		}
		compute_prefix(nwords, (const uint32_t*) addr, preflen, &prefix[0]);
		return hashmap_remove(&p->prefix[preflen], &prefix[0], len);
	}


	void lpm_clear(lpm* p, lpm_dtor_t dtor, void* arg)
	{
		for (unsigned n = 0; n <= LPM_MAX_PREFIX; n++) {
			lpm_hmap_t* hmap = &p->prefix[n];

			if (!hmap->hashsize) {
				assert(!hmap->bucket);
				continue;
			}
			for (unsigned i = 0; i < hmap->hashsize; i++) {
				lpm_ent_t* entry = hmap->bucket[i];

				while (entry) {
					lpm_ent_t* next = entry->next;

					if (dtor) {
						dtor(arg, entry->key,
							entry->len, entry->val);
					}
					free(entry);
					entry = next;
				}
			}
			free(hmap->bucket);
			hmap->bucket = NULL;
			hmap->hashsize = 0;
			hmap->nitems = 0;
		}
		if (dtor) {
			dtor(arg, zero_address, 4, p->defvals[0]);
			dtor(arg, zero_address, 16, p->defvals[1]);
		}
		memset(p->bitmask, 0, sizeof(p->bitmask));
		memset(p->defvals, 0, sizeof(p->defvals));
	}


	lpm_table::lpm_table()
		: m_lpm(std::make_unique<lpm>())
	{}

	lpm_table::~lpm_table()
	{
		lpm_clear(m_lpm.get(), NULL, NULL);
	}

	bool lpm_table::v4_insert(const net::ip::network_v4& addr, lpm_tag target)
	{
		const int len = 4;
		const unsigned nwords = LPM_TO_WORDS(len);
		uint32_t prefix[nwords];
		lpm_ent_t* entry;
		auto& instance = *m_lpm;

		auto preflen = addr.prefix_length();
		if (preflen == 0) {
			/* 0-length prefix is a special case. */
			instance.defvals[LPM_LEN_IDX(len)] = target;
			return true;
		}

		auto int_addr = (uint32_t)addr.address().to_uint();
		compute_prefix(nwords, &int_addr, preflen, prefix);
		entry = hashmap_insert(&instance.prefix[preflen], prefix, len);
		if (entry) {
			const unsigned n = --preflen >> 5;
			instance.bitmask[n] |= 0x80000000U >> (preflen & 31);
			entry->val = target;
			return true;
		}

		return false;
	}

	bool lpm_table::v6_insert(const net::ip::network_v6& addr, lpm_tag target)
	{
		const int len = 16;
		const unsigned nwords = LPM_TO_WORDS(len);
		uint32_t prefix[nwords];
		lpm_ent_t* entry;
		auto& instance = *m_lpm;

		auto preflen = addr.prefix_length();
		if (preflen == 0) {
			/* 0-length prefix is a special case. */
			instance.defvals[LPM_LEN_IDX(len)] = target;
			return true;
		}

		auto int_addr = addr.address().to_bytes();
		compute_prefix(nwords, (const uint32_t*)&int_addr[0], preflen, prefix);
		entry = hashmap_insert(&instance.prefix[preflen], prefix, len);
		if (entry) {
			const unsigned n = --preflen >> 5;
			instance.bitmask[n] |= 0x80000000U >> (preflen & 31);
			entry->val = target;
			return true;
		}

		return false;
	}

	bool lpm_table::v4_remove(const net::ip::network_v4& addr)
	{
		const int len = 4;
		auto int_addr = addr.address().to_uint();
		int ret = lpm_remove(m_lpm.get(), (const void*)&int_addr, len, addr.prefix_length());
		if (ret != 0)
			return false;
		return true;
	}

	bool lpm_table::v6_remove(const net::ip::network_v6& addr)
	{
		const int len = 16;
		auto byte_addr = addr.address().to_bytes();
		int ret = lpm_remove(m_lpm.get(), (const void*)&byte_addr[0], len, addr.prefix_length());
		if (ret != 0)
			return false;
		return true;
	}

	lpm_tag lpm_table::lookup(const net::ip::address& addr)
	{
		const int len = addr.is_v4() ? 4 : 16;
		const unsigned nwords = LPM_TO_WORDS(len);
		unsigned i, n = nwords;
		std::vector<uint32_t> prefix(nwords, 0);
		auto& instance = *m_lpm;
		const uint32_t* addr_ptr = nullptr;
		uint32_t uaddr = 0;
		net::ip::address_v6::bytes_type byte_addr;
		if (len == 4)
		{
			uaddr = (uint32_t)addr.to_v4().to_uint();
			addr_ptr = &uaddr;
		}
		else
		{
			byte_addr = addr.to_v6().to_bytes();
			addr_ptr = (const uint32_t*)&byte_addr[0];
		}

		while (n--) {
			uint32_t bitmask = instance.bitmask[n];

			while ((i = ffs_template(bitmask)) != 0) {
				const unsigned preflen = (32 * n) + (32 - --i);
				lpm_hmap_t* hmap = &instance.prefix[preflen];
				lpm_ent_t* entry;

				compute_prefix(nwords, addr_ptr, preflen, &prefix[0]);
				entry = hashmap_lookup(hmap, &prefix[0], len);
				if (entry) {
					return entry->val;
				}
				bitmask &= ~(1U << i);
			}
		}

		return instance.defvals[LPM_LEN_IDX(len)];
	}

}
