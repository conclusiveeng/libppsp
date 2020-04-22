#ifndef _PEER_H_
#define _PEER_H_

#include "types.h"

struct peer {

	enum { LEECHER, SEEDER } type;
	
	// swarm_id

	u32 src_chan_id;
	u32 dest_chan_id;
	struct node *tree;
	u32 nl;			// number of leaves
	u32 nc;			// number of chunks
	
	char *handshake_req;
	int handshake_req_len;
	char *handshake_resp;
	int handshake_resp_len;
	char *request;
	int request_len;

	
	// ponizsze to chyba powinny byc w innej strukt - request
	u32 start_chunk;
	u32 end_chunk;
};


#endif
