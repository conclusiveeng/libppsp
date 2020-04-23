#include <stdio.h>
#include <string.h>
#include <endian.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>


#include "net.h"
#include "types.h"
#include "ppspp_protocol.h"
#include "sha1.h"
#include "mt.h"

// handshake protocol options
enum proto_options { VERSION = 0, MINIMUM_VERSION, SWARM_ID, CONTENT_PROT_METHOD, MERKLE_HASH_FUNC, LIVE_SIGNATURE_ALG, CHUNK_ADDR_METHOD,  LIVE_DISC_WIND, 
	SUPPORTED_MSGS, CHUNK_SIZE, END_OPTION = 255 };

enum message { HANDSHAKE = 0, DATA, ACK, HAVE, INTEGRITY, PEX_RESV4, PEX_REQ, SIGNED_INTEGRITY, REQUEST, CANCEL, CHOKE, UNCHOKE, PEX_RESV6, PEX_RESCERT };
	
	





// procedura serializujaca opcje dla handshake'ingu
// przekazany tutaj ptr - musi wskazywac na zaallokowany obszar pamieci o wystraczajacej wielkosci zeby pomiescic wszystkie dane
// pos - wskaznik do struktury na podstawie ktorej bedzie tworzona lista opcji 
int make_handshake_options (char *ptr, struct proto_opt_str *pos)
{
	char *d;
	int ret;
	
	
	d = ptr;
	if (pos->opt_map & (1 << VERSION)) {					// rfc - 7.2
		*d++ = VERSION;
		*d++ = 1;
	} else {
		printf("no version specified - it's obligatory!\n");
		return -1;
	}
	

	if (pos->opt_map & (1 << MINIMUM_VERSION)) {				// rfc - 7.3
		*d++ = MINIMUM_VERSION;
		*d++ = 1;
	} else {
		printf("no minimum_version specified - it's obligatory!\n");
		return -1;
	}
	
	if (pos->opt_map & (1 << SWARM_ID)) {					// rfc - 7.4
		*d++ = SWARM_ID;
		*(u16 *)d = htobe16(pos->swarm_id_len & 0xffff);
		d += sizeof(pos->swarm_id_len);
		memcpy(d, pos->swarm_id, pos->swarm_id_len);
		d += pos->swarm_id_len;
	}
	
	if (pos->opt_map & (1 << CONTENT_PROT_METHOD)) {			// rfc - 7.5
		*d++ = CONTENT_PROT_METHOD;
		*d++ = pos->content_prot_method & 0xff;
	} else {
		printf("no content_integrity_protection_method specified - it's obligatory!\n");
		return -1;
	} 
	
	if (pos->opt_map & (1 << MERKLE_HASH_FUNC)) {			// rfc - 7.6
		*d++ = MERKLE_HASH_FUNC;
		*d++ = pos->merkle_hash_func & 0xff;
	} 
	
	if (pos->opt_map & (1 << LIVE_SIGNATURE_ALG)) {			// rfc - 7.7
		*d++ = LIVE_SIGNATURE_ALG;
		*d++ = pos->live_signature_alg & 0xff;
	} // sprawdzac czy ta opcja jest obowizakowa - rfc. 7.7 - kiedy Sign ALL
	
	
	if (pos->opt_map & (1 << CHUNK_ADDR_METHOD)) {			// rfc - 7.8
		*d++ = CHUNK_ADDR_METHOD;
		*d++ = pos->chunk_addr_method & 0xff;
	} else {
		printf("no chunk_addr_method specified - it's obligatory!\n");
		return -1;
	} 
 
	if (pos->opt_map & (1 << LIVE_DISC_WIND)) {			// rfc - 7.9
		*d++ = LIVE_DISC_WIND;
		if ((pos->chunk_addr_method == 0) || (pos->chunk_addr_method == 2)) {		// table 6 - czy to 32-bitowe adresy?
			*(u32 *)d = htobe32(*(u32 *)pos->live_disc_wind);
			d += sizeof(u32);
		} else {
			*(u64 *)d = htobe64(*(u64 *)pos->live_disc_wind);
			d += sizeof(u64);
		}
	} else {
		printf("no chunk_addr_method specified - it's obligatory!\n");
		return -1;
	} 
	
	
	if (pos->opt_map & (1 << SUPPORTED_MSGS)) {			// rfc - 7.10
		*d++ = SUPPORTED_MSGS;
		*d++ = pos->supported_msgs_len & 0xff;
		memcpy(d, pos->supported_msgs, pos->supported_msgs_len & 0xff);
		d += pos->supported_msgs_len & 0xff;
	} 
	
	if (pos->opt_map & (1 << CHUNK_SIZE)) {			// rfc - 7.11
		*d++ = CHUNK_SIZE;
		*(u32 *)d = htobe32((u32)(pos->chunk_size & 0xffffffff));
		d += sizeof(pos->chunk_size);
	} else {
		printf("no chunk_size specified - it's obligatory!\n");
		return -1;
	} 

	*d++ = END_OPTION;				// zakoncz liste opcji znacznikiem 255
	

	ret = d - ptr;
	printf("%s returning: %u bytes\n", __FUNCTION__, ret);


	return ret;
}


// proc serializujaca poszczegolne bajty requestu HANDSHAKE
int make_handshake_request (char *ptr, u32 dest_chan_id, u32 src_chan_id, char *opts, int opt_len)
{
	char *d;
	int ret;
	
	d = ptr;
	
	*(u32 *)d = htobe32(dest_chan_id);
	d += sizeof(u32);

	*d = HANDSHAKE;
	d++;

	*(u32 *)d = htobe32(src_chan_id);
	d += sizeof(u32);
	
	memcpy(d, opts, opt_len);
	d += opt_len;
	
	ret = d - ptr;
	printf("%s: returning %u bytes\n", __FUNCTION__, ret);
	
	return ret;
}




// proc serializujaca poszczegolne bajty odpowiedzi HANDSHAKE
//int make_handshake_response (char *ptr, u32 dest_chan_id, u32 src_chan_id, char *opts, int opt_len, u32 start_chunk, u32 end_chunk)
//int make_handshake_have (char *ptr, u32 dest_chan_id, u32 src_chan_id, char *opts, int opt_len, u32 start_chunk, u32 end_chunk)
int make_handshake_have (char *ptr, u32 dest_chan_id, u32 src_chan_id, char *opts, int opt_len, struct peer *peer)
{
	char *d;
	int ret, len;

	// serialize HANDSHAKE header and options
	len = make_handshake_request(ptr, dest_chan_id, src_chan_id, opts, opt_len);

	d = ptr + len;
	
	// add HAVE header + data
	
	*d = HAVE;
	d++;
	
//	*(u32 *)d = htobe32(start_chunk);
	*(u32 *)d = htobe32(peer->start_chunk);
	d += sizeof(u32);

//	*(u32 *)d = htobe32(end_chunk);
	*(u32 *)d = htobe32(peer->end_chunk);
	d += sizeof(u32);
	
	
	
	ret = d - ptr;
	printf("%s: returning %u bytes\n", __FUNCTION__, ret);
	
	
	
	return ret;
}




int make_request (char *ptr, u32 dest_chan_id, u32 start_chunk, u32 end_chunk)
{
	char *d;
	int ret, len;

	d = ptr;
	
	*(u32 *)d = htobe32(dest_chan_id);
	d += sizeof(u32);
	
	*d = REQUEST;
	d++;
	
	*(u32 *)d = htobe32(start_chunk);
	d += sizeof(u32);
	*(u32 *)d = htobe32(end_chunk);
	d += sizeof(u32);

	*d = PEX_REQ;
	d++;
	
	ret = d - ptr;
	printf("%s: returning %u bytes\n", __FUNCTION__, ret);
	
	return ret;
}



int make_integrity (char *ptr, struct peer *peer)
{
	char *d;
	int x, y, ret;
	
	d = ptr;

	*(u32 *)d = htobe32(peer->dest_chan_id);
	d += sizeof(u32);


	*d = INTEGRITY;
	d++;
	
	*(u32 *)d = htobe32(peer->start_chunk);
	d += sizeof(u32);
	*(u32 *)d = htobe32(peer->end_chunk);
	d += sizeof(u32);
	
	y = 0;
	for (x = peer->start_chunk; x <= peer->end_chunk; x++) {
		memcpy(d, peer->tree[2 * x].sha, 20);
		printf("copying chunk: %u\n", x);
		y++;
		d += 20;
	}
	
	ret = d - ptr;
	printf("%s: returning %u bytes\n", __FUNCTION__, ret);
	
	return ret;
}




// wywolywany przez seedera - przygotowanie paczki danych (chunka) do wyslania
int make_data (char *ptr, struct peer *peer, struct req *req)
{
	char *d;
	int x, y, ret, fd, l;
	u64 timestamp;
	
	d = ptr;

	*(u32 *)d = htobe32(peer->dest_chan_id);
	d += sizeof(u32);


	*d = INTEGRITY;
	d++;
	
	*(u32 *)d = htobe32(peer->start_chunk);
	d += sizeof(u32);
	*(u32 *)d = htobe32(peer->end_chunk);
	d += sizeof(u32);

	timestamp = 0x12345678f11ff00f;		// tymczasowo tylko taki timestamp
	*(u64 *)d = htobe64(timestamp);
	d += sizeof(u64);
	
	fd = open(req->fname, O_RDONLY);
	if (fd < 0) {
		printf("error opening file: %s\n", req->fname);
		return -1;
	}

	lseek(fd, req->curr_chunk * peer->chunk_size, SEEK_SET);
	
	l = read(fd, d, peer->chunk_size);
	if (l < 0) {
		printf("error opening file: %s\n", req->fname);
		close(fd);
		return -1;
	}

	close(fd);

	if (l != peer->chunk_size) {
		printf("something wrong with reading file: %s, wanted: %u bytes but read: %u\n", req->fname, peer->chunk_size, l);
		//return -1;
	}
	
	d += l;


	ret = d - ptr;
	printf("%s: returning %u bytes\n", __FUNCTION__, ret);

	return ret;
}



// wywolywany przez seedera - przygotowanie paczki danych (chunka) do wyslania
int make_ack (char *ptr, struct peer *peer, struct req *req)
{
	char *d;
	int x, y, ret, fd, l;
	u64 delay_sample;
	uint64_t z;
	
	d = ptr;

	*(u32 *)d = htobe32(peer->dest_chan_id);
	d += sizeof(u32);


	*d = ACK;
	d++;

	
	*(u32 *)d = htobe32(req->curr_chunk);
	d += sizeof(u32);
	*(u32 *)d = htobe32(req->curr_chunk);
	d += sizeof(u32);
	
	delay_sample = 0x12345678ABCDEF;		// tymczasowo tylko taki delay sample
	*(u64 *)d = htobe64(delay_sample);
	d += sizeof(u64);
	
	ret = d - ptr;
	//printf("%s: returning %u bytes\n", __FUNCTION__, ret);

	return ret;
}















int dump_options (char *ptr, struct peer *peer)
{
	char *d;
	int swarm_len, x;
	u8 chunk_addr_method;
	u32 ldw32;
	u64 ldw64;
	u8 supported_msgs_len;
	int ret;
	
	d = ptr;
	
	if (*d == VERSION) {
		d++;
		printf("version: %u\n", *d);
		d++;
	}
	
	if (*d == MINIMUM_VERSION) {
		d++;
		printf("minimum_version: %u\n", *d);
		d++;
	}
	
	if (*d == SWARM_ID) {
		d++;
		swarm_len = be16toh(*((u16 *)d) & 0xffff);
		d += 2;
		printf("swarm_id[%u]: %s\n", swarm_len, d);
		d += swarm_len;
	}
	
	if (*d == CONTENT_PROT_METHOD) {
		d++;
		printf("Content integrity protection method: ");
		switch (*d) {
			case 0:	printf("No integrity protection\n"); break;
			case 1: printf("Merkle Hash Tree\n"); break;
			case 2: printf("Hash All\n"); break;
			case 3: printf("Unified Merkle Tree\n"); break;
			default: printf("Unassigned\n"); break;
		}
		d++;
	}
		
	if (*d == MERKLE_HASH_FUNC) {
		d++;
		printf("Merkle Tree Hash Function: ");
		switch (*d) {
			case 0:	printf("SHA-1\n"); break;
			case 1: printf("SHA-224\n"); break;
			case 2: printf("SHA-256\n"); break;
			case 3: printf("SHA-384\n"); break;
			case 4: printf("SHA-512\n"); break;
			default: printf("Unassigned\n"); break;
		}
		d++;
	}
	
	if (*d == LIVE_SIGNATURE_ALG) {
		d++;
		printf("Live Signature Algorithm: %u\n", *d);
		d++;
	}
	
	chunk_addr_method = 255;  // tylko do zaznaczenia bledu - tzn ze nie bylo opcji chunk_addr_method - a np. nastepna opcja live_disc_wind bedzie a ona wymaga tej chunk_addr_method
	if (*d == CHUNK_ADDR_METHOD) {
		d++;
		
		printf("Chunk Addressing Method: ");
		switch (*d) {
			case 0:	printf("32-bit bins\n"); break;
			case 1:	printf("64-bit byte ranges\n"); break;
			case 2:	printf("32-bit chunk ranges\n"); break;
			case 3:	printf("64-bit bins\n"); break;
			case 4:	printf("64-bit chunk ranges\n"); break;
			default: printf("Unassigned\n"); break;
		}
		chunk_addr_method = *d;
		d++;
	}
	
	if (*d == LIVE_DISC_WIND) {
		d++;
		printf("Live Discard Window: ");
		switch (chunk_addr_method) {
			case 0:
			case 2:	ldw32 =  be32toh(*(u32 *)d); printf("32bit: %#x\n", ldw32); d += sizeof(u32); break;
			case 1:
			case 3:
			case 4:	ldw64 =  be64toh(*(u64 *)d); printf("64bit: %#lx\n", ldw64); d += sizeof(u64); break;
			default: printf("Error\n");
		}
	}
	
	if (*d == SUPPORTED_MSGS) {
		d++;
		printf("Supported messages mask: ");
		supported_msgs_len = *d;
		d++;
		for (x = 0; x < supported_msgs_len; x++)
			printf("%#x ", *(d+x) & 0xff);
		printf("\n");
		d += supported_msgs_len;
	}
	
	if (*d == CHUNK_SIZE) {
		d++;
		printf("Chunk size: %u\n", be32toh(*(u32 *)d));
		if (peer->type == LEECHER) {		// tylko LEECHER ma aktualizowac u siebie chunk_size od seedera a nie na odwrot
			peer->chunk_size = be32toh(*(u32 *)d);
		}
		d += sizeof(u32);
	}
	
	if ((*d & 0xff) == END_OPTION) {
		printf("end option\n");
		d++;
	} else printf("error: should be END_OPTION(0xff) but is: %u\n", *d & 0xff);
	

	printf("parsed: %u bytes\n", d - ptr);
	
	ret = d - ptr;
	return ret;
}




// seeder to wywoluje zeby odebrac dane od leechera
int dump_handshake_request (char *ptr, int req_len, struct peer *peer)
{
	char *d;
	u32 dest_chan_id, src_chan_id;
	int ret, opt_len;
	
	d = ptr;
	
	dest_chan_id = be32toh(*(u32 *)d);
	printf("Destination Channel ID: %#x\n", dest_chan_id);
	d += sizeof(u32);

	if (*d == HANDSHAKE) {
		printf("ok, HANDSHAKE req\n");
	} else {
		printf("error - should be HANDSHAKE req (0) but is: %u\n", *d);
	}
	d++;
	
	src_chan_id = be32toh(*(u32 *)d);
	printf("Destination Channel ID: %#x\n", src_chan_id);
	d += sizeof(u32);
	
	// tutaj od wskaznika 'd' znajduja sie opcje - zdumpuj je
	printf("\n");
	
	opt_len = dump_options(d, peer);
	
	ret = d + opt_len - ptr;
	printf("%s returning: %u bytes\n", __FUNCTION__, ret);

	return ret;
}





// leecher to wywoluje - zeby rozparsowac HANDSHAKE+HAVE
//int dump_handshake_response (char *ptr, int resp_len, struct peer *peer)
int dump_handshake_have (char *ptr, int resp_len, struct peer *peer)
{
	char *d;
	int req_len, x;
	int ret;
	u32 start_chunk, end_chunk, num_chunks;
	
	// dump HANDSHAKE header and protocol options 
	d = ptr;
	req_len = dump_handshake_request(ptr, resp_len, peer);
	
	d += req_len;
	// dump HAVE header
	printf("HAVE header:\n");
	if (*d == HAVE) {
		printf("ok, HAVE header\n");
	} else {
		printf("error, should be HAVE header but is: %u\n", *d);
		return -1;
	}

	d++;
	
	start_chunk = be32toh(*(u32 *)d);
	d += sizeof(u32);
	peer->start_chunk = start_chunk;
	printf("start chunk: %u\n", start_chunk);
	
	end_chunk = be32toh(*(u32 *)d);
	d += sizeof(u32);
	peer->end_chunk = end_chunk;
	printf("end chunk: %u\n", end_chunk);
	
	// oblicz ile chunkow ma seeder
	num_chunks = end_chunk - start_chunk + 1;
	printf("seeder have %u chunks\n", num_chunks);
	peer->nc = num_chunks;


//	peer->nc = end_chunk - start_chunk + 1;
	peer->nl = 1 << order2(peer->nc);
	printf("------------------nc: %u nl: %u\n", peer->nc, peer->nl);

	
#warning FIXME przez tego ifa pojawia sie segv
	if (peer->chunk == NULL) {
		peer->chunk = malloc(peer->nl * sizeof(struct chunk));
		memset(peer->chunk, 0, peer->nl * sizeof(struct chunk));
	} else {
		printf("error - peer->chunk has already allocated memory, HAVE should be send only once\n");
		//return -1;
		abort();
	}


	
	
	ret = d - ptr;
	printf("%s returning: %u bytes\n", __FUNCTION__, ret);
	
	return ret;
}




//int dump_request (char *ptr, int req_len)
int dump_request (char *ptr, int req_len, struct peer *peer)
{
	char *d;
	int ret;
	u32 dest_chan_id;
	u32 start_chunk, end_chunk;
	
	d = ptr;

	dest_chan_id = be32toh(*(u32 *)d);
	printf("Destination Channel ID: %#x\n", dest_chan_id);
	d += sizeof(u32);

	
	if (*d == REQUEST) {
		printf("ok, REQUEST header\n");
	} else {
		printf("error, should be REQUEST header but is: %u\n", *d);
		return -1;
	}
	d++;

	start_chunk = be32toh(*(u32 *)d);
	d += sizeof(u32);
	printf("start chunk: %u\n", start_chunk);
	
	end_chunk = be32toh(*(u32 *)d);
	d += sizeof(u32);
	printf("end chunk: %u\n", end_chunk);
	
	if (peer->type == SEEDER) {
			peer->start_chunk = start_chunk;
			peer->end_chunk = end_chunk;
	}
	
	
	
	// tutaj obsluga pozostalych komunikatow - jak np. PEX_REQ
	if (d - ptr < req_len) {
		printf("here do in the future maintenance of rest of messages: %u bytes left\n" ,req_len - (d - ptr));
	}
	
	
	
	
	ret = d - ptr;
	printf("%s returning: %u bytes\n", __FUNCTION__, ret);

	return ret;
}





int dump_integrity (char *ptr, int req_len, struct peer *peer)
{
	char *d;
	int ret, x;
	u32 dest_chan_id, start_chunk, end_chunk, nc;
	
	d = ptr;

	dest_chan_id = be32toh(*(u32 *)d);
	printf("Destination Channel ID: %#x\n", dest_chan_id);
	d += sizeof(u32);

	if (*d == INTEGRITY) {
		printf("ok, INTEGRITY header\n");
	} else {
		printf("error, should be INTEGRITY header but is: %u\n", *d);
		return -1;
	}
	d++;
	
	start_chunk = be32toh(*(u32 *)d);
	d += sizeof(u32);
	printf("start chunk: %u\n", start_chunk);
	
	end_chunk = be32toh(*(u32 *)d);
	d += sizeof(u32);
	printf("end chunk: %u\n", end_chunk);
	
	nc = end_chunk - start_chunk + 1;

	printf("pozostalo: %u bajtow, czyli teoretycznie %u hashy, powinno byc: %u\n", req_len - (d - ptr), (req_len - (d - ptr)) / 20, nc);

	
#if 0	
	// na razie alokuj tab chunkow i skopiuj tam odebrane chunki a potem trzeba je przeniesc do lisci drzewka
	
 
	peer->nc = end_chunk - start_chunk + 1;
	peer->nl = 1 << order2(peer->nc);
	printf("------------------nc: %u nl: %u\n", peer->nc, peer->nl);
	
	
	////// mallloc powinien byc w dump_have

	if (peer->chunk == NULL) {
		peer->chunk = malloc(peer->nl * sizeof(struct chunk));
		memset(peer->chunk, 0, peer->nl * sizeof(struct chunk));
	}
#endif
	for (x = start_chunk; x <= end_chunk; x++) {
		memcpy(peer->chunk[x].sha, d, 20);
		peer->chunk[x].state = CH_ACTIVE;
		peer->chunk[x].offset = (x - start_chunk) * peer->chunk_size;
		peer->chunk[x].len = peer->chunk_size;
#warning FIXME .len jest poprawnie poza ostatnim chunkiem
		
		d += 20;
		//printf("dumping chunk %u\n", x);
	}
//	d += nc * 20;
	
	if (req_len - (d - ptr) > 0)
		printf("pozostalo: %u bajtow, rozparsowac je\n", req_len - (d - ptr));
	
	
	ret = d - ptr;
	printf("%s returning: %u bytes\n", __FUNCTION__, ret);

	return ret;
	
	
}


int dump_ack (char *ptr, int ack_len, struct peer *peer)
{
	char *d;
	int ret, x;
	u32 dest_chan_id, start_chunk, end_chunk, nc;
	u64 delay_sample;
	
	d = ptr;

	dest_chan_id = be32toh(*(u32 *)d);
	printf("Destination Channel ID: %#x\n", dest_chan_id);
	d += sizeof(u32);

	if (*d == ACK) {
		printf("ok, ACK header\n");
	} else {
		printf("error, should be ACK header but is: %u\n", *d);
		return -1;
	}
	d++;

	
	start_chunk = be32toh(*(u32 *)d);
	d += sizeof(u32);
	printf("start chunk: %u\n", start_chunk);
	
	end_chunk = be32toh(*(u32 *)d);
	d += sizeof(u32);
	printf("end chunk: %u\n", end_chunk);
	
	
	delay_sample = be64toh(*(u64 *)d);
	d += sizeof(u64);
	printf("delay_sample: %#lx\n", delay_sample);
	
	
	
	
	
	ret = d - ptr;
	printf("%s returning: %u bytes\n", __FUNCTION__, ret);

	return ret;

}






void proto_test (struct peer *peer, struct req *req)
{
	struct proto_opt_str pos;
	char swarm_id[] = "swarm_id";
	char opts[128];			// bufor na zakodowane opcje
	char handshake_req[256], handshake_resp[256], request[256];
	int opts_len, h_req_len, h_resp_len, req_len;
	u32 num_chunks; ///  do usuniecia - jak tylko bedzie pobieranie danych z handshake+have 
	
	memset(&pos, 0, sizeof(struct proto_opt_str));
	memset(&opts, 0, sizeof(opts));
	memset(&handshake_req, 0, sizeof(handshake_req));
	memset(&handshake_resp, 0, sizeof(handshake_resp));
	
	
	// prepare structure as a set of parameters to make_handshake_options() proc
	pos.version = 1;
	pos.minimum_version = 1;
	pos.swarm_id_len = strlen(swarm_id);
	pos.swarm_id = swarm_id;
	pos.content_prot_method = 1;			// merkle hash tree
	pos.merkle_hash_func = 0;			// 0 = sha-1
	pos.live_signature_alg = 0;			// trzeba wziac jakas wartosc z dnssec
	pos.chunk_addr_method = 2;			// 2 = 32 bit chunk ranges
	*(unsigned int *)pos.live_disc_wind = 0x12345678;		// 32 bitowa wartosc - ale chyba trzbe ja przekodowac? albo raczej w make_handshake_options()
	pos.supported_msgs_len = 2;			// przykladowo 2 bajty mapy bitowej obslugiwanych komend
	*(unsigned int *)pos.supported_msgs = 0xffff;			// mapa bitowa: obslugujemy wszystkie komendy rfc
	pos.chunk_size = peer->chunk_size;
	
	// mark the options we want to pass to make_handshake_options() (which ones are valid)
	pos.opt_map = 0;
	pos.opt_map |= (1 << VERSION);
	pos.opt_map |= (1 << MINIMUM_VERSION);
	pos.opt_map |= (1 << SWARM_ID);
	pos.opt_map |= (1 << CONTENT_PROT_METHOD);
	pos.opt_map |= (1 << MERKLE_HASH_FUNC);
	pos.opt_map |= (1 << LIVE_SIGNATURE_ALG);
	pos.opt_map |= (1 << CHUNK_ADDR_METHOD);
	pos.opt_map |= (1 << LIVE_DISC_WIND);
	pos.opt_map |= (1 << SUPPORTED_MSGS);
	pos.opt_map |= (1 << CHUNK_SIZE);


	// to dla leechera
	opts_len = make_handshake_options(opts, &pos);
	dump_options(opts, peer);
	printf("\n\ninitial handshake:\n");
	// make initial HANDSHAKE request - serialize dest chan id, src chan id and protocol options
	h_req_len = make_handshake_request(handshake_req, 0, 0xfeedbabe, opts, opts_len);
	dump_handshake_request(handshake_req, h_req_len, peer);
	

	// to dla seedera
	printf("\n\nresponse handshake (have):\n");
	// make response HANDSHAKE with 0-10 chunks available
	printf("+++++++start: %u  end: %u\n", peer->start_chunk, peer->end_chunk);
//	h_resp_len = make_handshake_have(handshake_resp, 0, 0xfeedbabe, opts, opts_len, peer->start_chunk, peer->end_chunk);		// tu poprawic channel id
	h_resp_len = make_handshake_have(handshake_resp, 0, 0xfeedbabe, opts, opts_len, peer);		// tu poprawic channel id
	//if (peer->type == SEEDER)
	//	dump_handshake_have(handshake_resp, h_resp_len, peer);


	// ponizsze przeniesione do net_leecher - bo to tam ma byc
	/*
	// to dla leechera
	printf("\n\nrequest:\n");
	num_chunks = 7; 
#warning FIXME num_chunks should be get from seeder - seeder sends HAVE where those data are embedded
	printf("------------num_chunks: %u\n", num_chunks);
	req_len = make_request(request, 0xfeedbabe, 0, num_chunks - 1);
	dump_request(request, req_len);
	*/
	
	
	if (peer->type == SEEDER) {
		// uzupelnij pola struktury peer - od zera sa one ustawiane w mt.c::main()
		peer->handshake_resp = handshake_resp;
		peer->handshake_resp_len = h_resp_len;
		net_seeder(peer, req);					// uruchom serwer udostepniajacy plik
	} else {
		peer->handshake_req = handshake_req;
		peer->handshake_req_len = h_req_len;
		peer->request = request;
		peer->request_len = req_len;
//		net_leecher(peer);					// uruchom klienta odbierajacego plik
		net_leecher(peer, req);					// uruchom klienta odbierajacego plik
	}
}



