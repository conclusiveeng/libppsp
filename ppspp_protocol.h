
#ifndef _PPSPP_PROTOCOL_H_
#define _PPSPP_PROTOCOL_H_

#include "mt.h"
#include "peer.h"


/* handshake protocol options */
enum proto_options { VERSION = 0, MINIMUM_VERSION, SWARM_ID, CONTENT_PROT_METHOD, MERKLE_HASH_FUNC, LIVE_SIGNATURE_ALG, CHUNK_ADDR_METHOD,  LIVE_DISC_WIND, 
	SUPPORTED_MSGS, CHUNK_SIZE, FILE_SIZE, FILE_NAME, END_OPTION = 255 };

enum message { HANDSHAKE = 0, DATA, ACK, HAVE, INTEGRITY, PEX_RESV4, PEX_REQ, SIGNED_INTEGRITY, REQUEST, CANCEL, CHOKE, UNCHOKE, PEX_RESV6, PEX_RESCERT };

enum handshake_type { HANDSHAKE_INIT = 1, HANDSHAKE_FINISH, HANDSHAKE_ERROR };


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
	uint8_t file_name[256];
	uint8_t file_name_len;

	uint32_t opt_map;				/* bitmap - which of the fields above have any data */
};


int make_handshake_options (char *, struct proto_opt_str *);
int make_handshake_request (char *, uint32_t, uint32_t, char *, int);
int make_handshake_have (char *, uint32_t, uint32_t, char *, int, struct peer *);
int make_handshake_finish (char *, struct peer *);
int make_request (char *, uint32_t, uint32_t, uint32_t);
int make_integrity (char *, struct peer *, struct peer *);
int make_data (char *, struct peer *);
int make_ack (char *, struct peer *);
int dump_options (char *ptr, struct peer *);
int dump_handshake_request (char *, int, struct peer *);
int dump_handshake_have (char *, int, struct peer *);
int dump_request (char *, int, struct peer *);
int dump_integrity (char *, int, struct peer *);
int dump_ack (char *, int, struct peer *);
uint8_t message_type (char *);
uint8_t handshake_type (char *);
void proto_test (struct peer *);

#endif
