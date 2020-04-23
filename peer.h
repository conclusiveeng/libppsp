#ifndef _PEER_H_
#define _PEER_H_

#include "types.h"

struct peer {

	enum { LEECHER, SEEDER } type;
	
	

	u32 src_chan_id;
	u32 dest_chan_id;
	struct node *tree;		// wskaznik na poczatek (index 0) tablicy z wezlami drzewka - czyli calego drzewka
	struct node *tree_root;		// wskaznik na root (korzen) drzewka ->tree
	struct chunk *chunk;		// tablica ze zdalnymi hashami sciagnieta na leechera przy pomocy INTEGRITY
	struct chunk *chunk_verify;	// tablica loklana - z obliczonymi lokalnie hashami do weryfikacji z powyzsza tab ->chunk
	u32 nl;				// number of leaves
	u32 nc;				// number of chunks

	

	char *handshake_req;
	int handshake_req_len;
	char *handshake_resp;
	int handshake_resp_len;
	char *request;
	int request_len;


	// pobrane z opcji HANDSHAKE - w dump_options()
	u32 chunk_size;
	// swarm_id
	
	
	
	// ponizsze to chyba powinny byc w innej strukt - request
	u32 start_chunk;
	u32 end_chunk;
};





struct req {
	
	char *fname;
	u32 start_chunk;
	u32 end_chunk;
	u32 curr_chunk;		// aktualnie przetwarzany chunk
};






#endif
