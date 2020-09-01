/*
 * Copyright (c) 2020 Conclusive Engineering Sp. z o.o.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdio.h>
#include <string.h>
#ifdef __FreeBSD__
#include <sys/endian.h>
#endif
#ifdef __gnu_linux__
#include <endian.h>
#endif
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libgen.h>

#include "net.h"
#include "ppspp_protocol.h"
#include "sha1.h"
#include "mt.h"
#include "debug.h"
#include "peer.h"


/*
 * serialize handshake options in memory in form of list
 *
 * in params:
 * 	pos -  pointer to structure with options
 *
 * out params:
 * 	ptr - pointer to buffer where the serialized options will be placed
 */
INTERNAL_LINKAGE int
ppspp_make_handshake_options (char *ptr, struct proto_opt_str *pos)
{
	unsigned char *d;
	int ret;

	d = (unsigned char *)ptr;
	if (pos->opt_map & (1 << VERSION)) {
		*d = VERSION;
		d++;
		*d = 1;
		d++;
	} else {
		d_printf("%s", "no version specified - it's obligatory!\n");
		return -1;
	}

	if (pos->opt_map & (1 << MINIMUM_VERSION)) {
		*d = MINIMUM_VERSION;
		d++;
		*d = 1;
		d++;
	} else {
		d_printf("%s", "no minimum_version specified - it's obligatory!\n");
		return -1;
	}

	if (pos->opt_map & (1 << SWARM_ID)) {
		*d = SWARM_ID;
		d++;
		*(uint16_t *)d = htobe16(pos->swarm_id_len & 0xffff);
		d += sizeof(pos->swarm_id_len);
		memcpy(d, pos->swarm_id, pos->swarm_id_len);
		d += pos->swarm_id_len;
	}

	if (pos->opt_map & (1 << CONTENT_PROT_METHOD)) {
		*d = CONTENT_PROT_METHOD;
		d++;
		*d = pos->content_prot_method & 0xff;
		d++;
	} else {
		d_printf("%s", "no content_integrity_protection_method specified - it's obligatory!\n");
		return -1;
	}

	if (pos->opt_map & (1 << MERKLE_HASH_FUNC)) {
		*d = MERKLE_HASH_FUNC;
		d++;
		*d = pos->merkle_hash_func & 0xff;
		d++;
	}

	if (pos->opt_map & (1 << LIVE_SIGNATURE_ALG)) {
		*d = LIVE_SIGNATURE_ALG;
		d++;
		*d = pos->live_signature_alg & 0xff;
		d++;
	}

	if (pos->opt_map & (1 << CHUNK_ADDR_METHOD)) {
		*d = CHUNK_ADDR_METHOD;
		d++;
		*d = pos->chunk_addr_method & 0xff;
		d++;
	} else {
		d_printf("%s", "no chunk_addr_method specified - it's obligatory!\n");
		return -1;
	}

	if (pos->opt_map & (1 << LIVE_DISC_WIND)) {
		*d = LIVE_DISC_WIND;
		d++;
		if ((pos->chunk_addr_method == 0) || (pos->chunk_addr_method == 2)) {		/* 32 or 64 bit addresses */
			*(uint32_t *)d = htobe32(*(uint32_t *)pos->live_disc_wind);
			d += sizeof(uint32_t);
		} else {
			*(uint64_t *)d = htobe64(*(uint64_t *)pos->live_disc_wind);
			d += sizeof(uint64_t);
		}
	} else {
		d_printf("%s", "no live_disc_method specified - it's obligatory!\n");
		/* return -1; */
	}

	if (pos->opt_map & (1 << SUPPORTED_MSGS)) {
		*d = SUPPORTED_MSGS;
		d++;
		*d = pos->supported_msgs_len & 0xff;
		d++;
		memcpy(d, pos->supported_msgs, pos->supported_msgs_len & 0xff);
		d += pos->supported_msgs_len & 0xff;
	}

	if (pos->opt_map & (1 << CHUNK_SIZE)) {
		*d = CHUNK_SIZE;
		d++;
		*(uint32_t *)d = htobe32((uint32_t)(pos->chunk_size & 0xffffffff));
		d += sizeof(pos->chunk_size);
	} else {
		d_printf("%s", "no chunk_size specified - it's obligatory!\n");
		/* return -1; */
	}

	/*
	 * extension to original PPSPP protocol
	 * format: 1 + 8 bytes
	 *
	 * uint8_t  = FILE_SIZE marker = 10
	 * uint64_t = big-endian encoded length of file
	 */
	if (pos->opt_map & (1 << FILE_SIZE)) {
		*d = FILE_SIZE;
		d++;
		*(uint64_t *)d = htobe64(pos->file_size);
		d += sizeof(uint64_t);
	} else {
		d_printf("%s", "no file_size specified - it's obligatory!\n");
		/* return -1; */
	}

	/*
	 * extension to original PPSPP protocol
	 * format: 1 + 1 + max 255 bytes
	 *
	 * uint8_t = FILE_NAME marker = 11
	 * uint8_t = length of the file name
	 * uint8_t [0..255] file name
	 */
	if (pos->opt_map & (1 << FILE_NAME)) {
		*d = FILE_NAME;
		d++;
		*d = pos->file_name_len & 0xff;
		d++;
		memset(d, 0, 255);
		memcpy(d, pos->file_name, pos->file_name_len);
		d += pos->file_name_len;
	} else {
		d_printf("%s", "no file_name specified - it's obligatory!\n");
		/* return -1; */
	}

	/*
	 * extension to original PPSPP protocol
	 * format: 1 + 20 bytes
	 *
	 * uint8_t = FILE_HASH marker = 12
	 * uint8_t[20] = SHA1 hash of the file the LEECHER wants to download from SEEDER
	 */

	if (pos->opt_map & (1 << FILE_HASH)) {
		*d = FILE_HASH;
		d++;
		memcpy(d, pos->sha_demanded, 20);
		d += 20;
	} else {
		d_printf("%s", "no file_hash specified - it's obligatory!\n");
		/* return -1; */
	}

	*d = END_OPTION;				/* end the list of options with 0xff marker */
	d++;

	ret = d - (unsigned char *)ptr;
	d_printf("%s returning: %u bytes\n", __func__, ret);

	return ret;
}


/*
 * make structure of handshake request
 *
 * in params:
 * 	dest_chan_id - destination channel id
 * 	src_chan_id - source channel id
 * 	opts - pointer to generated list of PPSPP protocol options
 * 	opt_len - length of the option list in bytes
 * out params:
 * 	ptr - pointer to buffer where data will be stored
 *
 */
INTERNAL_LINKAGE int
ppspp_make_handshake_request (char *ptr, uint32_t dest_chan_id, uint32_t src_chan_id, char *opts, int opt_len)
{
	size_t pos = 0;

	pos += ppspp_pack_dest_chan(ptr + pos, dest_chan_id);
	pos += ppspp_pack_handshake(ptr + pos, src_chan_id, opts, opt_len);
	return (pos);
}

/*
 * generate set of HAVE messages basing on that if given bit in number of chunks is set or not
 * if set - make proper HAVE subrange
 * in other words - make HAVE cache
 */
INTERNAL_LINKAGE int
ppspp_make_handshake_have (char *ptr, uint32_t dest_chan_id, uint32_t src_chan_id, char *opts, int opt_len, struct peer *peer)
{
	char *d;
	int ret, len;
	uint32_t b, i, v, nc;

	/* serialize HANDSHAKE header and options */
	len = ppspp_make_handshake_request(ptr, dest_chan_id, src_chan_id, opts, opt_len);

	/* alloc memory for HAVE cache */
	peer->have_cache = malloc(1024 * sizeof(struct have_cache));
	peer->num_have_cache = 0;

	d = ptr + len;
	nc = peer->file_list_entry->end_chunk - peer->file_list_entry->start_chunk + 1;

	b = 31;				/* starting bit for scanning of bits */
	i = 0;				/* iterator */
	v = 0;
	while (i < 32) {
		if (nc & (1 << b)) {		/* if the bit on position "b" is set? */
			d_printf("HAVE: %u..%u\n", v, v + (1 << b) - 1);

			/* add HAVE header + data */
			*d = HAVE;
			d++;

			*(uint32_t *)d = htobe32(v);
			d += sizeof(uint32_t);
			peer->have_cache[peer->num_have_cache].start_chunk = v;

			*(uint32_t *)d = htobe32(v + (1 << b) - 1);
			d += sizeof(uint32_t);
			peer->have_cache[peer->num_have_cache].end_chunk = v + (1 << b) - 1;

			v = v + (1 << b);
			peer->num_have_cache++;
		}
		i++;
		b--;
	}

	d_printf("num_have_cache: %u\n", peer->num_have_cache);

	ret = d - ptr;
	d_printf("%s: returning %u bytes\n", __func__, ret);

	return ret;
}


/*
 * creates finishing (closing) HANDSHAKE request
 * called by LEECHER
 *
 * in params:
 * 	peer - pointer to structure describing LEECHER
 * out params:
 * 	ptr - pointer to buffer where data will be stored
 *
 */
INTERNAL_LINKAGE int
ppspp_make_handshake_finish (char *ptr, struct peer *peer)
{
	unsigned char *d;
	int ret;

	d = (unsigned char *)ptr;

	*(uint32_t *)d = htobe32(0xfeed1234);				/* temporarily */
	d += sizeof(uint32_t);

	*d = HANDSHAKE;
	d++;

	*(uint32_t *)d = htobe32(0x0);
	d += sizeof(uint32_t);

	*d = END_OPTION;
	d++;

	ret = d - (unsigned char *)ptr;
	d_printf("%s: returning %u bytes\n", __func__, ret);

	return ret;
}


/*
 * create REQUEST with range of chunks
 * called by LEECHER
 *
 * in params:
 * 	dest_chan_id - destination channel id
 * 	start_chunk - number of first chunk
 * 	end_chunk - number of end chunk
 *
 * out params:
 * 	ptr - pointer to buffer where data of this request should be placed
 */
INTERNAL_LINKAGE int
ppspp_make_request (char *ptr, uint32_t dest_chan_id, uint32_t start_chunk, uint32_t end_chunk, struct peer *peer)
{
	size_t pos = 0;

	pos += ppspp_pack_dest_chan(ptr + pos, dest_chan_id);
	pos += ppspp_pack_request(ptr + pos, start_chunk, end_chunk);

	if (peer->pex_required != 0)
		pos += ppspp_pack_pex_req(ptr + pos);

	return (pos);
}


/*
 * make packet with data of our seeder which shares complete file
 * list of seeders is taken from commandline with "-l" option
 */
INTERNAL_LINKAGE int
ppspp_make_pex_resp (char *ptr, struct peer *peer, struct peer *we)
{
	size_t pos = 0;
	int ret, addr_size;
	uint16_t space, max_pex, pex;
	struct other_seeders_entry *e;

	/* first - check if there are any entries in altenatieve seeders list */
	/* if list is empty then return 0 and don't send any repsonse for PEX_REQ */
	if (SLIST_EMPTY(&we->other_seeders_list_head))
		return (0);

	pos += ppspp_pack_dest_chan(ptr + pos, peer->dest_chan_id);

	/* calculate amount of available space in UDP payload */
	/* 1500 - 20(ip) - 8(udp) - 4(chanid) */
	space = 1500 - 20 - 8 - 4;
	addr_size = 4 + 2;  /* 4 - ip, 2- port */
	max_pex = space / addr_size;

	d_printf("we're sending PEX_RESP to: %s\n", inet_ntoa(peer->leecher_addr.sin_addr));


	/* IP addresses taken from "-l" commandline option: -l ip1:port1,ip2:port2,ip3:port3 ...etc */
	pex = 0;
	SLIST_FOREACH(e, &we->other_seeders_list_head, next) {
		pos += ppspp_pack_pex_resv4(ptr + pos, e->sa.sin_addr.s_addr, e->sa.sin_port);
		pex++;
		if (pex >= max_pex)
			break;
	}

	return (pos);
}

/*
 * uses bitmap for remembering which nodes have already been sent in INTEGRITY
 *
 */
INTERNAL_LINKAGE int
ppspp_make_integrity_reverse (char *ptr, struct peer *peer, struct peer *we)
{
	char *d;
	int ret, ic, f;
	struct node *n, *s, l, r, *e, *n_subroot;
	struct integrity_temp *it, *it2;
	int16_t iti, itn, iti2, itn2;
	uint32_t b, i, v, nc, v_start, v_end, v_root;

	d = ptr;

	*(uint32_t *)d = htobe32(peer->dest_chan_id);
	d += sizeof(uint32_t);

	_assert(peer->file_list_entry != NULL, "%s", "peer->file_list_entry should be != NULL\n");
	_assert(peer->integrity_bmp != NULL, "%s", "peer->integrity_bmp should be != NULL\n");

	it = malloc(1024 * sizeof(struct integrity_temp));
	_assert(it != NULL, "%s", "it should be != NULL\n");
	itn = 0;

	it2 = malloc(1024 * sizeof(struct integrity_temp));
	_assert(it2 != NULL, "%s", "it2 should be != NULL\n");
	itn2 = 0;

	_assert(peer->curr_chunk <= peer->file_list_entry->nc, "curr_chunk must be <= nc, but curr_chunk: %lu and nc: %u\n", peer->curr_chunk, peer->file_list_entry->nc);

	/* to be compatible with libswift determine subranges
	 * example for num_chunks == 7:
	 * 0..3=4, 4..5=2, 6..6=1
	 * 7=(111)2 - for every bit set (b2, b1, b0) determine subrange equal to weight of given bit
	 * for b2 set it will be subrange: 0..3 - because b2 has weight 4
	 * for b1 set it will be next subrange 4..5 - because b1 has weight 2
	 * for b0 set it will be next subrange 6..6 - because b0 has weight 1
	 */
	nc = peer->file_list_entry->end_chunk - peer->file_list_entry->start_chunk + 1;
	b = 31;
	i = 0;
	v = 0;
	while (i < 32) {
		if (nc & (1 << b)) {
			d_printf("INTEGRITY: %u..%u\n", v, v + (1 << b) - 1);

			v_start = v;
			v_end = v + (1 << b) - 1;
			it[itn].start_chunk = v_start;		/* start of subrange */
			it[itn].end_chunk = v_end;		/* end of subrange */

			v_root = v_start + v_end;
			e = &peer->file_list_entry->tree[v_root]; /* "e" is subroot of subtree v..v+(1<<b)-1 */

			if (!(peer->integrity_bmp[v_root / 8] & (1 << (v_root % 8)))) {
				memcpy(it[itn].sha, e->sha, 20);
				d_printf("it[%u] %u..%u\n", itn, it[itn].start_chunk, it[itn].end_chunk);
				itn++;
				peer->integrity_bmp[v_root / 8] |= (1 << (v_root % 8));		/* update INTEGRITY bitmap */
			}
			v = v + (1 << b);
		}
		i++;
		b--;
	}

	/* here there is algorithm generating siblings - it goes from bottom of the tree (leaves of the tree)
	 * to the subroot of the subtree for given HAVE cache entry
	 * next we need to reverse the the output from this alogithm list of INTEGRITY to be compatible with libswift
	 */

	n = &peer->file_list_entry->tree[peer->curr_chunk * 2];		/* node for given curr_chunk */

	/* looks in HAVE cache for the subrange where there is curr_chunk */
	ic = 0;
	f = 0;
	while (ic < peer->num_have_cache) {
		d_printf("have_cache[%u]: start: %u  end: %u\n", ic, peer->have_cache[ic].start_chunk, peer->have_cache[ic].end_chunk);
		if ((peer->curr_chunk >= peer->have_cache[ic].start_chunk) && (peer->curr_chunk <= peer->have_cache[ic].end_chunk)) {
			f = 1;
			break;
		}
		ic++;
	}

	_assert(f == 1, "f must be equal 1 but it has: %u value\n", f);

	/* determine subroot for curr_chunk and given HAVE subtree
	 * "ic" is pointing to index of subrange in peer->have_cache
	 */
	n_subroot = &peer->file_list_entry->tree[peer->have_cache[ic].start_chunk + peer->have_cache[ic].end_chunk];
	d_printf("subroot for subrange: %u..%u is: %u\n", peer->have_cache[ic].start_chunk, peer->have_cache[ic].end_chunk, n_subroot->number);

	while ((n != n_subroot) && (n->parent != NULL)) {
		/* which children the node "n" is? left or right from paren point of view? */
		if (n == n->parent->left) {
			s = n->parent->right;		/* sibling for "n" node is right node */
		} else {
			s = n->parent->left;		/* sibling for "n" node is left node */
		}

		if (!(peer->integrity_bmp[s->number / 8] & (1 << (s->number % 8)))) {
			interval_min_max(s, &l, &r);
			it2[itn2].start_chunk = l.number / 2;
			it2[itn2].end_chunk = r.number / 2;
			memcpy(it2[itn2].sha, s->sha, 20);
			itn2++;
			peer->integrity_bmp[s->number / 8] |= (1 << (s->number % 8));
		} else d_printf("INTEGRITY already sent: %u skip it\n", s->number);

		/* go up - to parent of current "n" */
		n = n->parent;
	}

	/* here we are reversing output of above algorithm to be compatible with libswift */
	if (itn2 > 0) {
		iti2 = itn2 - 1;
		while (iti2 >= 0) {
			d_printf("it2[%u] %u..%u\n", iti2, it2[iti2].start_chunk, it2[iti2].end_chunk);
			it[itn].start_chunk = it2[iti2].start_chunk;
			it[itn].end_chunk = it2[iti2].end_chunk;
			memcpy(it[itn].sha, it2[iti2].sha, 20);
			iti2--;
			itn++;
		}
	}

	/* finally for each of generated subranges - generate INTEGRITY entries */
	for (iti = 0; iti < itn; iti++) {
		d_printf("INTEGRITY[%u] (%u..%u)\n", iti, it[iti].start_chunk, it[iti].end_chunk);
		*d = INTEGRITY;
		d++;
		*(uint32_t *)d = htobe32(it[iti].start_chunk);
		d += sizeof(uint32_t);
		*(uint32_t *)d = htobe32(it[iti].end_chunk);
		d += sizeof(uint32_t);
		memcpy(d, it[iti].sha, 20);
		d += 20;
	}

	free(it);
	free(it2);

	ret = d - ptr;
	d_printf("%s: returning %u bytes\n", __func__, ret);

	return ret;
}

INTERNAL_LINKAGE int
ppspp_make_data (char *ptr, struct peer *peer)
{
	size_t pos = 0;

	pos += ppspp_pack_dest_chan(ptr + pos, peer->dest_chan_id);
	pos += ppspp_make_data_no_chanid(ptr + pos, peer);
	return (pos);
}


/* this procedure is not sending dest_chan_id (4 bytes) on the beginning because DATA message can be concatenated
 * with another kind of message
 */
INTERNAL_LINKAGE int
ppspp_make_data_no_chanid (char *ptr, struct peer *peer) {
	size_t pos = 0;
	int fd, l;
	uint64_t timestamp;

	timestamp = 0x12345678f11ff00f;                /* temporarily */


	pos += ppspp_pack_data(ptr + pos, peer->curr_chunk, peer->curr_chunk, timestamp);

	fd = open(peer->file_list_entry->path, O_RDONLY);
	if (fd < 0) {
		d_printf("error opening file2: %s\n", peer->file_list_entry->path);
		abort();
		return -1;
	}

	lseek(fd, peer->curr_chunk * peer->chunk_size, SEEK_SET);

	l = read(fd, ptr + pos, peer->chunk_size);
	if (l < 0) {
		d_printf("error reading file: %s\n", peer->fname);
		close(fd);
		return -1;
	}

	close(fd);

	pos += l;
	return (pos);
}

INTERNAL_LINKAGE int
ppspp_make_have_ack(char *ptr, struct peer *peer)
{
	size_t pos = 0;
	uint64_t delay_sample = 0x12345678ABCDEF;

	pos += ppspp_pack_dest_chan(ptr, peer->dest_chan_id);
	pos += ppspp_pack_have(ptr + pos, peer->curr_chunk, peer->curr_chunk);
	pos += ppspp_pack_ack(ptr + pos, peer->curr_chunk, peer->curr_chunk, delay_sample);
	return (pos);
}

INTERNAL_LINKAGE
int ppspp_dump_options (char *ptr, struct peer *peer)
{
	char *d;
	int swarm_len, x, ret;
	uint8_t chunk_addr_method, supported_msgs_len;
	uint32_t ldw32;
	uint64_t ldw64;
	struct file_list_entry *fi;

	d = ptr;

	if (*d == VERSION) {
		d++;
		d_printf("version: %u\n", *d);
		if (*d != 1) {
			d_printf("version should be 1 but is: %u\n", *d);
			abort();
		}
		d++;
	}

	if (*d == MINIMUM_VERSION) {
		d++;
		d_printf("minimum_version: %u\n", *d);
		d++;
	}

	if (*d == SWARM_ID) {
		d++;
		swarm_len = be16toh(*((uint16_t *)d) & 0xffff);
		d += 2;
		/* d_printf("swarm_id[%u]: %s\n", swarm_len, d); 	swarm_id are binary data so don't print them */

		if (1) {
			SLIST_FOREACH(fi, &peer->seeder->file_list_head, next) {
				if (memcmp(fi->tree_root->sha, d, 20) == 0) {
					peer->file_list_entry = fi;		/* set pointer to selected file by leecher using SHA1 hash */
					d_printf("leecher wants file: %s\n", fi->path);
					break;
				}
			}
		}

		d += swarm_len;
	}

	if (*d == CONTENT_PROT_METHOD) {
		d++;
		d_printf("%s", "Content integrity protection method: ");
		switch (*d) {
			case 0:	d_printf("%s", "No integrity protection\n"); break;
			case 1: d_printf("%s", "Merkle Hash Tree\n"); break;
			case 2: d_printf("%s", "Hash All\n"); break;
			case 3: d_printf("%s", "Unified Merkle Tree\n"); break;
			default: d_printf("%s", "Unassigned\n"); break;
		}
		d++;
	}

	if (*d == MERKLE_HASH_FUNC) {
		d++;
		d_printf("%s", "Merkle Tree Hash Function: ");
		switch (*d) {
			case 0:	d_printf("%s", "SHA-1\n"); break;
			case 1: d_printf("%s", "SHA-224\n"); break;
			case 2: d_printf("%s", "SHA-256\n"); break;
			case 3: d_printf("%s", "SHA-384\n"); break;
			case 4: d_printf("%s", "SHA-512\n"); break;
			default: d_printf("%s", "Unassigned\n"); break;
		}
		d++;
	}

	if (*d == LIVE_SIGNATURE_ALG) {
		d++;
		d_printf("Live Signature Algorithm: %u\n", *d);
		d++;
	}

	chunk_addr_method = 255;
	if (*d == CHUNK_ADDR_METHOD) {
		d++;
		d_printf("%s", "Chunk Addressing Method: ");
		switch (*d) {
			case 0:	d_printf("%s", "32-bit bins\n"); break;
			case 1:	d_printf("%s", "64-bit byte ranges\n"); break;
			case 2:	d_printf("%s", "32-bit chunk ranges\n"); break;
			case 3:	d_printf("%s", "64-bit bins\n"); break;
			case 4:	d_printf("%s", "64-bit chunk ranges\n"); break;
			default: d_printf("%s", "Unassigned\n"); break;
		}
		chunk_addr_method = *d;
		d++;
	}

	if (*d == LIVE_DISC_WIND) {
		d++;
		d_printf("%s", "Live Discard Window: ");
		switch (chunk_addr_method) {
			case 0:
			case 2:	ldw32 =  be32toh(*(uint32_t *)d); d_printf("32bit: %#x\n", ldw32); d += sizeof(uint32_t); break;
			case 1:
			case 3:
			case 4:	ldw64 =  be64toh(*(uint64_t *)d); d_printf("64bit: %#lx\n", ldw64); d += sizeof(uint64_t); break;
			default: d_printf("%s", "Error\n");
		}
	}

	if (*d == SUPPORTED_MSGS) {
		d++;
		d_printf("%s", "Supported messages mask: ");
		supported_msgs_len = *d;
		d++;
		for (x = 0; x < supported_msgs_len; x++)
			d_printf("%#x ", *(d+x) & 0xff);
		d_printf("%s", "\n");
		d += supported_msgs_len;
	}

	if (*d == CHUNK_SIZE) {
		d++;
		d_printf("Chunk size: %u\n", be32toh(*(uint32_t *)d));
		if (peer->type == LEECHER) {
			peer->chunk_size = be32toh(*(uint32_t *)d);
		}
		d += sizeof(uint32_t);
	}


	if ((*d & 0xff) == END_OPTION) {
		d_printf("%s", "end option\n");
		d++;
	} else {
		d_printf("error: should be END_OPTION(0xff) but is: d[%lu]: %u\n", d - ptr, *d & 0xff);
		abort();
	}

	if ((peer->type == LEECHER) && (peer->chunk_size == 0)) {
		d_printf("%s", "SEEDER didn't send chunk_size option - setting it locally to default value of 1024\n");
		peer->chunk_size = 1024;
	}

	d_printf("parsed: %lu bytes\n", d - ptr);

	ret = d - ptr;
	return ret;
}

INTERNAL_LINKAGE int
ppspp_dump_handshake_request (char *ptr, int req_len, struct peer *peer) {
	char *d;
	uint32_t src_chan_id;
	int ret, opt_len;

	d = ptr;

	if (*d == HANDSHAKE) {
		d_printf("%s", "ok, HANDSHAKE req\n");
	} else {
		d_printf("error - should be HANDSHAKE req (0) but is: %u\n", *d);
		abort();
	}
	d++;

	src_chan_id = be32toh(*(uint32_t *) d);
	d_printf("Source Channel ID: %#x\n", src_chan_id);
	peer->dest_chan_id = src_chan_id;                /* set remote peer's channel id - take it from seeders's handshake response */
	d += sizeof(uint32_t);

	opt_len = ppspp_dump_options(d, peer);

	/* allocate memory for integrity bitmap for mark which tree nodes has already been sent do leecher (swift compatibility mode)
	 * it will replace "peer->state == SENT"
	 */
	if (peer->integrity_bmp == NULL) {
		peer->integrity_bmp = malloc(2 * peer->file_list_entry->nl / 8);
		_assert(peer->integrity_bmp != NULL, "%s\n",
			"peer->integrity_bmp should be != NULL");
		memset(peer->integrity_bmp, 0, 2 * peer->file_list_entry->nl / 8);
	} else {
		d_printf("%s", "integrity_bmp already allocated\n");
		abort();
	}

	peer->data_bmp = malloc(2 * peer->file_list_entry->nl / 8);
	_assert(peer->data_bmp != NULL, "%s\n", "peer->data_bmp should be != NULL");
	memset(peer->data_bmp, 0, 2 * peer->file_list_entry->nl / 8);

	ret = d + opt_len - ptr;
	d_printf("%s returning: %u bytes\n", __func__, ret);

	return ret;
}

/* for leecher
 */
INTERNAL_LINKAGE int
ppspp_dump_handshake_have (char *ptr, int resp_len, struct peer *peer)
{
	char *d;
	int req_len, ret;
	uint32_t start_chunk, end_chunk, num_chunks, nr_chunk;

	/* allocate memory for HAVE cache - it will be using by leecher scheduler */
	peer->have_cache = malloc(1024 * sizeof(struct have_cache));
	_assert(peer->have_cache != NULL, "%s\n", "peer->have_cache should be != NULL");
	peer->num_have_cache = 0;

	/* dump HANDSHAKE header and protocol options */
	d = ptr;
	req_len = ppspp_dump_handshake_request(ptr, resp_len, peer);

	d += req_len;

	end_chunk = 0;
	while ((*d == HAVE) && (d - ptr < resp_len)) {
		/* dump HAVE header */
		d_printf("%s", "HAVE header:\n");
		if (*d == HAVE) {
			d_printf("%s", "ok, HAVE header\n");
		} else {
			d_printf("error, should be HAVE header but is: %u\n", *d);
			abort();
		}

		d++;

		nr_chunk = be32toh(*(uint32_t *)d);
		peer->have_cache[peer->num_have_cache].start_chunk = nr_chunk;	/* save start_chunk number in HAVE cache */
		d_printf("start chunk: %u\n", nr_chunk);
		if (nr_chunk < start_chunk)
			start_chunk = nr_chunk;
		d += sizeof(uint32_t);

		nr_chunk = be32toh(*(uint32_t *)d);
		peer->have_cache[peer->num_have_cache].end_chunk = nr_chunk;	/* save end_chunk number in HAVE cache */
		d_printf("end chunk: %u\n", nr_chunk);
		if (nr_chunk > end_chunk)
			end_chunk = nr_chunk;
		d += sizeof(uint32_t);
		peer->num_have_cache++;				/* increment number of HAVE cache entries */
	}

	d_printf("created HAVE cache with %u entries\n", peer->num_have_cache);

	peer->start_chunk = start_chunk;
	d_printf("final: start chunk: %u\n", start_chunk);
	peer->end_chunk = end_chunk;
	d_printf("final: end chunk: %u\n", end_chunk);

	/* calculate how many chunks seeder has */
	num_chunks = end_chunk - start_chunk + 1;
	d_printf("seeder has %u chunks\n", num_chunks);
	peer->nc = num_chunks;
	if (peer->local_leecher)
		peer->local_leecher->nc = num_chunks;

	/* calculate number of leaves */
	peer->nl = 1 << order2(peer->nc);
	if (peer->local_leecher)
		peer->local_leecher->nl = peer->nl;
	d_printf("nc: %u nl: %u\n", peer->nc, peer->nl);

	if (peer->local_leecher) {
		if (peer->local_leecher->chunk_size == 0)
			peer->local_leecher->chunk_size = peer->chunk_size;
	}

	if (peer->chunk == NULL) {
		peer->chunk = malloc(peer->nl * sizeof(struct chunk));
		memset(peer->chunk, 0, peer->nl * sizeof(struct chunk));

		/* do we really need this allocation? */
		if (peer->local_leecher) {
			peer->local_leecher->chunk = malloc(peer->nl * sizeof(struct chunk));
			memset(peer->local_leecher->chunk, 0, peer->nl * sizeof(struct chunk));
		}
	} else {
		d_printf("%s", "error - peer->chunk has already allocated memory, HAVE should be send only once\n");
	}

	if (peer->download_schedule == NULL) {
		/* don't create download_schedule[] here for step-by-step mode because it will be created in other procedure for sbs */
		if (peer->sbs_mode == 0) {
			peer->download_schedule = malloc(peer->nl * sizeof(struct schedule_entry));
			memset(peer->download_schedule, 0, peer->nl * sizeof(struct schedule_entry));
			ppspp_create_download_schedule(peer);
		}
	} else {
		d_printf("%s", "error - peer->download_schedule has already allocated memory, HAVE should be send only once\n");
	}

	ret = d - ptr;
	d_printf("%s returning: %u bytes\n", __func__, ret);

	return ret;
}

INTERNAL_LINKAGE int
ppspp_dump_request (char *ptr, int req_len, struct peer *peer)
{
	char *d;
	int ret;
	uint32_t start_chunk, end_chunk;

	d = ptr;

	if (*d == REQUEST) {
		d_printf("%s", "ok, REQUEST header\n");
	} else {
		d_printf("error, should be REQUEST header but is: %u\n", *d);
		abort();
	}
	d++;

	start_chunk = be32toh(*(uint32_t *)d);
	d += sizeof(uint32_t);
	d_printf("  start chunk: %u\n", start_chunk);

	end_chunk = be32toh(*(uint32_t *)d);
	d += sizeof(uint32_t);
	d_printf("  end chunk: %u\n", end_chunk);

	_assert(peer->type == LEECHER, "%s\n", "Only leecher is allowed to run this procedure");

	if (peer->type == LEECHER) {
		peer->start_chunk = start_chunk;
		peer->end_chunk = end_chunk;
	}

	if (*d == PEX_REQ) {
		peer->pex_required = 1;
		d++;
	}

	if (d - ptr < req_len) {
		d_printf("  here do in the future maintenance of rest of messages: %lu bytes left\n", req_len - (d - ptr));
	}

	ret = d - ptr;
	d_printf("%s returning: %u bytes\n", __func__, ret);

	return ret;
}


/*
 * parse PEX_RESV4
 * called by LEECHER
 *
 */
INTERNAL_LINKAGE int
dump_pex_resp (char *ptr, int req_len, struct peer *peer, int sockfd)
{
	char *d;
	int ret;
	uint16_t pex, max_pex, space, addr_size;
	uint32_t dest_chan_id;
	struct peer *c;
	struct sockaddr_in sa;

	d = ptr;

	dest_chan_id = be32toh(*(uint32_t *)d);
	d_printf("Destination Channel ID: %#x\n", dest_chan_id);
	d += sizeof(uint32_t);

	if (*d == PEX_RESV4) {
		d_printf("%s", "ok, PEX_RESV4 header\n");
	} else {
		d_printf("error, should be PEX_RESV4 header but is: %u\n", *d);
		abort();
	}
	d++;

	addr_size = sizeof(sa.sin_addr.s_addr) + sizeof(sa.sin_port);	/* 4 bytes IP address, 2 bytes port */
	space = req_len - (d - ptr);
	max_pex = space / addr_size;

	if (peer->current_seeder == NULL) {
		/* add primary seeder as a first entry to the peer_list_head list */
		memcpy(&sa.sin_addr.s_addr, &peer->seeder_addr.sin_addr.s_addr, sizeof(sa.sin_addr.s_addr));
		sa.sin_port = peer->seeder_addr.sin_port;
		c = new_seeder(&sa, BUFSIZE);
		c->sockfd = sockfd;

		pthread_mutex_lock(&peer->peers_list_head_mutex);
		add_peer_to_list(&peer->peers_list_head, c);
		pthread_mutex_unlock(&peer->peers_list_head_mutex);

		/* initially set current_seeder on primary seeder */
		peer->current_seeder = c;

		d_printf("[__] %s:%u\n", inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));

		d_printf("max_pex: %u\n", max_pex);
		pex = 0;
		while (pex < max_pex) {
			memcpy(&sa.sin_addr.s_addr, d, sizeof(sa.sin_addr.s_addr));
			d += sizeof(sa.sin_addr.s_addr);
			memcpy(&sa.sin_port, d, sizeof(sa.sin_port));
			d += sizeof(sa.sin_port);

			d_printf("[%u] %s:%u\n", pex, inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));

			c = new_seeder(&sa, BUFSIZE);
			c->sockfd = sockfd;
			pthread_mutex_lock(&peer->peers_list_head_mutex);
			add_peer_to_list(&peer->peers_list_head, c);
			pthread_mutex_unlock(&peer->peers_list_head_mutex);

			pex++;
		}
	}

	ret = d - ptr;
	d_printf("%s returning: %u bytes\n", __func__, ret);

	return ret;
}

INTERNAL_LINKAGE int
ppspp_dump_integrity (char *ptr, int req_len, struct peer *peer)
{
	char *d;
	char sha_buf[40 + 1];
	int ret, s, y;
	uint32_t dest_chan_id, start_chunk, end_chunk, node;

	d = ptr;

	dest_chan_id = be32toh(*(uint32_t *)d);
	d_printf("Destination Channel ID: %#x\n", dest_chan_id);
	d += sizeof(uint32_t);

	end_chunk = 0;
	while ((*d == INTEGRITY) && (d - ptr < req_len)) {
		if (*d == INTEGRITY) {
			d_printf("%s", "ok, INTEGRITY header\n");
		} else {
			d_printf("error, should be INTEGRITY header but is: %u\n", *d);
			abort();
		}
		d++;

		start_chunk = be32toh(*(uint32_t *)d);
		d_printf("  start chunk: %u\n", start_chunk);
		d += sizeof(uint32_t);

		end_chunk = be32toh(*(uint32_t *)d);
		d_printf("  end chunk: %u\n", end_chunk);
		d += sizeof(uint32_t);

		/* for example tree: 0,2,4,6 (indexes: 0,1,2,3) and range (start_chunk==0 and end_chunk==3) root node is 3
		 * root node for given subtree is a sum of start_chunk and end_chunk
		 */
		node = start_chunk + end_chunk;		/* calculate root node */

		d_printf("setting up node: %u\n", node);

		memcpy(peer->tree[node].sha, d, 20);
		peer->tree[node].state = ACTIVE;

		if (debug) {
			s = 0;
			for (y = 0; y < 20; y++)
				s += sprintf(sha_buf + s, "%02x", peer->tree[node].sha[y] & 0xff);
			sha_buf[40] = '\0';
			d_printf("dumping node %u:  %s\n", node, sha_buf);
		}
		d += 20;		/* jump over SHA-1 hash */
	}

	if (req_len - (d - ptr) > 0)
		d_printf("  %lu bytes left, parse them\n", req_len - (d - ptr));

	ret = d - ptr;
	d_printf("%s returning: %u bytes\n", __func__, ret);

	return ret;
}

INTERNAL_LINKAGE int
ppspp_dump_have_ack (char *ptr, int ack_len, struct peer *peer)
{
	char *d;
	int ret;
	uint32_t dest_chan_id, start_chunk, end_chunk;
	uint64_t delay_sample;

	d = ptr;

	dest_chan_id = be32toh(*(uint32_t *)d);
	d_printf("Destination Channel ID: %#x\n", dest_chan_id);
	d += sizeof(uint32_t);

	if (*d == HAVE) {
		d_printf("%s", "ok, HAVE header\n");
	} else {
		d_printf("error, should be HAVE header but is: %u\n", *d);
	}
	d++;

	start_chunk = be32toh(*(uint32_t *)d);
	d += sizeof(uint32_t);
	d_printf("start chunk: %u\n", start_chunk);

	end_chunk = be32toh(*(uint32_t *)d);
	d += sizeof(uint32_t);
	d_printf("end chunk: %u\n", end_chunk);

	if (d - ptr > ack_len) abort();

	if (*d == ACK) {
		d_printf("%s", "ok, ACK header\n");
		d++;

		start_chunk = be32toh(*(uint32_t *)d);
		d += sizeof(uint32_t);
		d_printf("start chunk: %u\n", start_chunk);

		end_chunk = be32toh(*(uint32_t *)d);
		d += sizeof(uint32_t);
		d_printf("end chunk: %u\n", end_chunk);

		delay_sample = be64toh(*(uint64_t *)d);
		d += sizeof(uint64_t);
		d_printf("delay_sample: %#lx\n", delay_sample);
	} else {
		d_printf("error, should be ACK header but is: %u\n", *d);
	}

	if (d - ptr > ack_len) abort();

	ret = d - ptr;
	d_printf("%s returning: %u bytes\n", __func__, ret);

	return ret;
}


/*
 * return type of message
 */
INTERNAL_LINKAGE uint8_t
ppspp_message_type (const char *ptr)
{
	const struct ppsp_msg *msg = (const struct ppsp_msg *)&ptr[4];

	return (msg->message_type);
}


/*
 * return type of HANDSHAKE: INIT, FINISH, ERROR
 */
INTERNAL_LINKAGE uint8_t
ppspp_handshake_type (char *ptr)
{
	char * d;
	uint32_t dest_chan_id, src_chan_id;
	uint8_t ret;

	d = ptr;

	dest_chan_id = be32toh(*(uint32_t *)d);
	d_printf("Destination Channel ID: %#x\n", dest_chan_id);
	d += sizeof(uint32_t);

	if (*d == HANDSHAKE) {
		d_printf("%s", "ok, HANDSHAKE header\n");
	} else {
		d_printf("error, should be HANDSHAKE header but is: %u\n", *d);
		abort();
	}
	d++;

	src_chan_id = be32toh(*(uint32_t *)d);
	d_printf("Destination Channel ID: %#x\n", dest_chan_id);
	d += sizeof(uint32_t);

	if ((dest_chan_id == 0x0) && (src_chan_id != 0x0)) {
		d_printf("%s", "handshake_init\n");
		ret = HANDSHAKE_INIT;
	}

	if ((dest_chan_id != 0x0) && (src_chan_id == 0x0)) {
		d_printf("%s", "handshake_finish\n");
		ret = HANDSHAKE_FINISH;
	}
	if ((dest_chan_id == 0x0) && (src_chan_id == 0x0)) {
		d_printf("%s", "handshake_error1\n");
		ret = HANDSHAKE_ERROR;
	}

	if ((dest_chan_id != 0x0) && (src_chan_id != 0x0)) {
		d_printf("%s", "handshake_error2\n");
		ret = HANDSHAKE_ERROR;
	}

	return ret;
}


INTERNAL_LINKAGE uint16_t
ppspp_count_handshake (char *ptr, uint16_t n, uint8_t skip_hdr)
{
	char *d;
	int swarm_len;
	uint8_t chunk_addr_method;
	uint16_t supported_msgs_len;

	d = ptr;

	if (skip_hdr)
		d += sizeof(uint32_t);		/* skip dest_chan_id */

	if (*d == HANDSHAKE) {
		d_printf("%s", "ok, HANDSHAKE req\n");
	} else {
		d_printf("error - should be HANDSHAKE req (0) but is: %u\n", *d);
		abort();
	}
	d++;

	d += sizeof(uint32_t);		/* skip src_chan_id */

	/* now the options */
	if (*d == VERSION)
		d += 2;

	if (*d == MINIMUM_VERSION)
		d += 2;

	if (*d == SWARM_ID) {
		d++;
		swarm_len = be16toh(*((uint16_t *)d) & 0xffff);
		d += 2;
		d += swarm_len;
	}

	if (*d == CONTENT_PROT_METHOD)
		d += 2;


	if (*d == MERKLE_HASH_FUNC)
		d += 2;

	if (*d == LIVE_SIGNATURE_ALG)
		d += 2;

	if (*d == CHUNK_ADDR_METHOD) {
		d++;
		chunk_addr_method = *d;
		d++;
	}

	if (*d == LIVE_DISC_WIND) {
		d++;
		switch (chunk_addr_method) {
			case 0:
			case 2:	d += sizeof(uint32_t); break;
			case 1:
			case 3:
			case 4:	d += sizeof(uint64_t); break;
			default: abort();
		}
	}

	if (*d == SUPPORTED_MSGS) {
		d++;
		supported_msgs_len = *d;
		d++;
		d += supported_msgs_len;
	}

	if (*d == CHUNK_SIZE) {
		d++;
		d += sizeof(uint32_t);
	}


	if ((*d & 0xff) == END_OPTION) {
		d_printf("%s", "end option\n");
		d++;
	} else {
		d_printf("error: should be END_OPTION(0xff) but is: d[%lu]: %u\n", d - ptr, *d & 0xff);
		abort();
	}

	d_printf("counted: %lu bytes\n", d - ptr);

	return d - ptr;
}
