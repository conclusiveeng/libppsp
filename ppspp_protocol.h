
#ifndef _PPSPP_PROTOCOL_H_
#define _PPSPP_PROTOCOL_H_

#include "types.h"
#include "mt.h"
#include "peer.h"


// handshake protocol options
enum proto_options { VERSION = 0, MINIMUM_VERSION, SWARM_ID, CONTENT_PROT_METHOD, MERKLE_HASH_FUNC, LIVE_SIGNATURE_ALG, CHUNK_ADDR_METHOD,  LIVE_DISC_WIND, 
	SUPPORTED_MSGS, CHUNK_SIZE, FILE_SIZE, FILE_NAME, END_OPTION = 255 };

enum message { HANDSHAKE = 0, DATA, ACK, HAVE, INTEGRITY, PEX_RESV4, PEX_REQ, SIGNED_INTEGRITY, REQUEST, CANCEL, CHOKE, UNCHOKE, PEX_RESV6, PEX_RESCERT };
	



struct proto_opt_str {
	uint8_t version;
	uint8_t minimum_version;
	uint16_t swarm_id_len;
	uint8_t *swarm_id;
	uint8_t content_prot_method;
	uint8_t merkle_hash_func;
	uint8_t live_signature_alg;
	uint8_t chunk_addr_method;
	uint8_t live_disc_wind[8];
	uint8_t supported_msgs_len;
	uint8_t supported_msgs[256];
	uint32_t chunk_size;
	uint64_t file_size;
	uint8_t file_name[256];			// a moze raczej jakis wskaznik?
	uint8_t file_name_len;

	uint32_t opt_map;				// mapa bitowa - ktore z powyzszych pol maja jakies dane
};




int make_handshake_options (char *ptr, struct proto_opt_str *pos);
int make_handshake_request (char *ptr, uint32_t dest_chan_id, uint32_t src_chan_id, char *opts, int opt_len);
int make_handshake_have (char *ptr, uint32_t dest_chan_id, uint32_t src_chan_id, char *opts, int opt_len, struct peer *peer);

int make_request (char *ptr, uint32_t dest_chan_id, uint32_t start_chunk, uint32_t end_chunk);
int make_integrity (char *ptr, struct peer *);
int make_integrity_v3 (char *ptr, struct peer *peer, struct peer *we);

//int make_data (char *ptr, struct peer *peer, struct req *req);
int make_data (char *ptr, struct peer *peer);
//int make_ack (char *ptr, struct peer *peer, struct req *req);
int make_ack (char *ptr, struct peer *peer);

int dump_options (char *ptr, struct peer *);
int dump_handshake_request (char *ptr, int req_len, struct peer *);
int dump_handshake_have (char *ptr, int resp_len, struct peer *);
int dump_request (char *ptr, int req_len, struct peer *);
int dump_integrity (char *ptr, int req_len, struct peer *);
int dump_ack (char *ptr, int req_len, struct peer *peer);
uint8_t message_type (char *ptr);
//void proto_test (struct peer *peer, struct req *req);
void proto_test (struct peer *peer);




#endif
