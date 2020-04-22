
#ifndef _PPSPP_PROTOCOL_H_
#define _PPSPP_PROTOCOL_H_

#include "types.h"
#include "mt.h"
#include "peer.h"

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




int make_handshake_options (char *ptr, struct proto_opt_str *pos);
int make_handshake_request (char *ptr, u32 dest_chan_id, u32 src_chan_id, char *opts, int opt_len);
int make_handshake_response (char *ptr, u32 dest_chan_id, u32 src_chan_id, char *opts, int opt_len, u32 start_chunk, u32 end_chunk);
int make_request (char *ptr, u32 dest_chan_id, u32 start_chunk, u32 end_chunk);
int make_integrity (char *ptr, struct peer *);

int dump_options (char *ptr);
int dump_handshake_request (char *ptr, int req_len, struct peer *);
int dump_handshake_response (char *ptr, int resp_len, struct peer *);
int dump_request (char *ptr, int req_len);
int dump_integrity (char *ptr, int req_len, struct peer *);

//void proto_test (int, u32, struct node *);
void proto_test (struct peer *peer);




#endif
