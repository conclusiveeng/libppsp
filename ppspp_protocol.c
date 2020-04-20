#include <stdio.h>
#include <string.h>

#include <endian.h>

// handshake protocol options
enum proto_options { VERSION = 0, MINIMUM_VERSION, SWARM_ID, CONTENT_PROT_METHOD, MERKLE_HASH_FUNC, LIVE_SIGNATURE_ALG, CHUNK_ADDR_METHOD,  LIVE_DISC_WIND, 
	SUPPORTED_MSGS, CHUNK_SIZE, END_OPTION = 255 };

	
typedef unsigned char u8;
typedef unsigned short int u16;
typedef unsigned int u32;
typedef unsigned long int  u64;



struct proto_opt_str {
	u8 version;
	u8 minimum_version;
	u16 swarm_id_len;
	u8 *swarm_id;
	u8 content_prot_method;
	u8 merkle_hash_func;
	u8 live_signature_alg;
	u8 chunk_addr_method;
	u8 live_disc_wind[8];
	u8 supported_msgs_len;
	u8 supported_msgs[256];
	u32 chunk_size;

	u32 opt_map;				// mapa bitowa - ktore z powyzszych pol maja jakies dane
};	





	
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

	*d++ = END_OPTION;				// zakoncz liste opjci znacznikiem 255
	

	ret = d - ptr;
	printf("%s returning: %u bytes\n", __FUNCTION__, ret);


	return ret;
}






void dump_options (char *ptr)
{
	char *d;
	int swarm_len, x;
	u8 chunk_addr_method;
	u32 ldw32;
	u64 ldw64;
	u8 supported_msgs_len;
	
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
		printf("Live Signture Algorithm: %u\n", *d);
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
			case 4:	ldw64 =  be64toh(*(u64 *)d); printf("64bit: %#x\n", ldw64); d += sizeof(u64); break;
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
		d += sizeof(u32);
	}
	
	if ((*d & 0xff) == END_OPTION) {
		printf("end option\n");
		d++;
	} else printf("error: should be END_OPTION(0xff) but is: %u\n", *d & 0xff);
	

	printf("parsed: %u bytes\n", d - ptr);
}








void proto_test (void)
{
	struct proto_opt_str pos;
	char swarm_id[] = "swarm_id";
	char opts[1024];			// bufor na zakodowane opcje
	
	memset(&pos, 0, sizeof(struct proto_opt_str));
	memset(&opts, 0, sizeof(opts));
	pos.version = 1;
	pos.minimum_version = 1;
	pos.swarm_id_len = strlen(swarm_id);
	pos.swarm_id = swarm_id;
	pos.content_prot_method = 1;			// merkle hash tree
	pos.merkle_hash_func = 0;			// 0 = sha-1
	pos.live_signature_alg = 0;			// trzeba wziac jakas wartosc z dnssec
	pos.chunk_addr_method = 0;			// 0 = 32 bit bins
	*(unsigned int *)pos.live_disc_wind = 0x12345678;		// 32 bitowa wartosc - ale chyba trzbe ja przekodowac? albo raczej w make_handshake_options()
	pos.supported_msgs_len = 2;			// przykladowo 2 bajty mapy bitowej obslugiwanych komend
	*(unsigned int *)pos.supported_msgs = 0xffff;			// mapa bitowa: obslugujemy wszystkie komendy rfc
	pos.chunk_size = 1024;				// domyslnie przymij 1024 bajty rozmiaru chunka 
	
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
	
	
	make_handshake_options(opts, &pos);
	
	dump_options(opts);
	
	
}



