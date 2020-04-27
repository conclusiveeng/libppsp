#ifndef _PEER_H_
#define _PEER_H_

#include <netinet/in.h>

#include "types.h"

struct peer {

	enum { LEECHER, SEEDER } type;
	enum { READY, BUSY } state;		// stan watku danego peer-a- albo gotowy do wykonania nowego zadania READY, albo wlasnie zajety BUSY
	

	uint32_t src_chan_id;
	uint32_t dest_chan_id;
	struct node *tree;		// wskaznik na poczatek (index 0) tablicy z wezlami drzewka - czyli calego drzewka
	struct node *tree_root;		// wskaznik na root (korzen) drzewka ->tree
	struct chunk *chunk;		// tablica ze zdalnymi hashami sciagnieta na leechera przy pomocy INTEGRITY
	struct chunk *chunk_verify;	// tablica loklana - z obliczonymi lokalnie hashami do weryfikacji z powyzsza tab ->chunk
	uint32_t nl;				// number of leaves
	uint32_t nc;				// number of chunks

	

	char *handshake_req;
	int handshake_req_len;
	char *handshake_resp;
	int handshake_resp_len;
	char *request;
	int request_len;


	// pobrane z opcji HANDSHAKE - w dump_options()
	uint32_t chunk_size;
	// swarm_id
	

	// sieciowe
//	struct in_addr sin_addr;
//	in_port_t sin_port;
	struct sockaddr_in sa;
	char *recv_buf;
	uint16_t recv_len;
	int sockfd;
	
	
	
	// ponizsze to chyba powinny byc w innej strukt - request
	uint32_t start_chunk;
	uint32_t end_chunk;
	uint64_t curr_chunk;		// aktualnie przetwarzany chunk
	uint64_t file_size;
	char fname[256];
	char fname_len;
};



struct two_peers {
	struct peer *we;		// struktura opisujaca "nasz" czyli localhost seedera
	struct peer *peer;		// sturktura zdalnego peera
};



/*
struct req {
	
	char *fname;
	char fname_len;
	uint64_t file_size;
	uint64_t start_chunk;
	uint64_t end_chunk;
	uint64_t curr_chunk;		// aktualnie przetwarzany chunk
};
*/


//struct peer * new_peer (struct sockaddr_in *sa, char *buf, int n, int sockfd);
struct peer * new_peer (struct sockaddr_in *sa, int n, int sockfd);


#endif
