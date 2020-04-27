#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <inttypes.h>

#include "mt.h"
#include "net.h"
#include "ppspp_protocol.h"
#include "peer.h"
#include "sha1.h"

#define BUFSIZE 1500
#define PORT    6778
#define IP "127.0.0.1"
//#define IP "192.168.1.64"

#define FILE_DOWNLOAD "download"


extern int h_errno;

struct peer we_local;

// serwer - udostepnia podany w command line plik
int net_seeder_v2(struct peer *peer)
{
	int sockfd;
	int portno;
	socklen_t clientlen;
	struct sockaddr_in serveraddr;
	struct sockaddr_in clientaddr;
	//struct hostent *hostp;
	char buf[BUFSIZE];
	//char *hostaddrp;
	int optval;
	int n, data_already_received;
	char *data_payload;
	uint64_t data_payload_len, cc;

	portno = PORT;

	
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
		printf("ERROR opening socket");

	optval = 1;
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int));

	bzero((char *) &serveraddr, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
	serveraddr.sin_port = htons((unsigned short)portno);

	if (bind(sockfd, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0)
		printf("ERROR on binding");

	clientlen = sizeof(clientaddr);

	data_payload = malloc(peer->chunk_size + 1 + 4 + 4 + 8);	//  chunksize + naglowki data: 1 + 4+ 4+ 8: rfc 8.6.

	data_already_received = 0;
	while (1) {
		
		
		// odbierz HANDSHAKE lub REQUEST
		if (data_already_received == 0) {
			bzero(buf, BUFSIZE);
			n = recvfrom(sockfd, buf, BUFSIZE, 0, (struct sockaddr *) &clientaddr, &clientlen);
			if (n < 0)
				printf("ERROR in recvfrom");
		}
		data_already_received = 0;

		
		if (message_type(buf) == HANDSHAKE) {
			// pokaz odebrany 1-szy handshake
			dump_handshake_request(buf, n, peer);

			// odeslij HANDSHAKE 2/3 + HAVE
			n = sendto(sockfd, peer->handshake_resp, peer->handshake_resp_len, 0, (struct sockaddr *) &clientaddr, clientlen);
			if (n < 0)
				printf("ERROR in sendto");
		}
		
		if (message_type(buf) == REQUEST) {
			// odbierz REQUEST (handshake 3/3)
			//bzero(buf, BUFSIZE);
			//n = recvfrom(sockfd, buf, BUFSIZE, 0, (struct sockaddr *) &clientaddr, &clientlen);
			// pokaz odebrany request
			dump_request(buf, n, peer);
			
			// rfc 5.6.2 - wyslij najpierw INTEGRITY z zadanymi hashami (0-6) a dopiero potem DATA
			n = make_integrity(buf, peer);
			
			// tu wyslij INTEGRITY z danymi
			n = sendto(sockfd, buf, n, 0, (struct sockaddr *) &clientaddr, clientlen);
			printf("INTEGRITY sent: %u\n", n);

			
			// utworz pakiet DATA z danymi chunka o numerze peer->curr_chunk
			for (cc = peer->start_chunk; cc <= peer->end_chunk; cc++) {
				peer->curr_chunk = cc;
				//data_payload_len = make_data(data_payload, peer, req);
				data_payload_len = make_data(data_payload, peer);
				
				// teraz wyslij osobny datagram z DATA 0
				n = sendto(sockfd, data_payload, data_payload_len, 0, (struct sockaddr *) &clientaddr, clientlen);
				printf("DATA[%lu] sent: %d (status: %d %s)\n", cc, n, errno, strerror(errno));
				
				// odbierz ACK
				bzero(buf, BUFSIZE);
				n = recvfrom(sockfd, buf, BUFSIZE, 0, (struct sockaddr *) &clientaddr, &clientlen);
				
				// najpierw sprawdz czy to na pewno ACK - jesli nie  - wyskocz z petli
				
				if (message_type(buf) == ACK) {
					// pokaz odebrany ACK
					dump_ack(buf, n, peer);
				} else { // tutaj wejsci ekiedy np. klient (leecher) mt przerwie transmisje np. przez ctrl-c i po chwili uruchomi nowa instancje mt
					printf("\ninny message: %u wyjscie z petli for\n", message_type(buf));
					data_already_received = 1;
					break;
				}
			}
		}
		
		
		
	}

	free(data_payload);

}







// klient - odbiorca pliku
//int net_leecher_v2(struct peer *peer, struct req *req)
int net_leecher_v2(struct peer *peer)
{
	int sockfd;
	char buffer[BUFSIZE];
	struct sockaddr_in servaddr;
	int n, x, s, y, fd, z, nr;
	socklen_t len;
	uint8_t *data_buffer;
	uint32_t data_buffer_len;
	SHA1Context context;
	uint8_t digest[20];
	char sha_buf[40 + 1];
	uint8_t cmp;
	uint64_t ack_len, cc;
	uint64_t num_series, hashes_per_mtu, rest, begin, end;
	char fname [256 + 32];
	
	len = sizeof(servaddr);
    
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket creation failed");
		exit(EXIT_FAILURE);
	}
  
	memset(&servaddr, 0, sizeof(servaddr));
      
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(PORT);
	servaddr.sin_addr.s_addr = inet_addr(IP);
      

	// wyslij handshake inicjujacy (pierwszy z trzech) - czyli probujemy nawiazac polaczenie z serwerem
	n = sendto(sockfd, peer->handshake_req, peer->handshake_req_len, 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
	if (n < 0) {
		printf("error sending handhsake: %d\n", n);
		return -1;
	}
	printf("initial message 1/3 sent\n");
         
	// odbierz odpowiedz serwera (handshake2) + have?
	n = recvfrom(sockfd, (char *)buffer, BUFSIZE, 0, (struct sockaddr *) &servaddr, &len);
	buffer[n] = '\0';
	printf("server replied with %u bytes\n", n);
	dump_handshake_have(buffer, n, peer);

	
	
	// oblicz ile bedzie serii i ile chunkow w jednej serii
	// ponizsza wielkosc 1500 (mtu) - moznaby sprametryzowac - np. z poziomu command line
	hashes_per_mtu = (1500 - (1 + 4 + 4 + 8 + 4))/20;		// 1+4+4+8+4: naglowek, 20-wielksoc pojedynczego hasha SHA-1
	printf("hashes_per_mtu: %lu ---------------\n", hashes_per_mtu);		// ile SHA-1 chunkow zmiesci sie w jednum MTU
	
	num_series = peer->nc / hashes_per_mtu;
	rest = peer->nc % hashes_per_mtu;
	printf("nc: %u   num_series: %lu   rest: %lu\n", peer->nc, num_series, rest);
	

	// tu chyba trzeba utworzyc drzewko o ilosci lisci peer->nl i przekopiowac tam sha z tab chunkow
	// tymczasowo zamiast pierwszego param jest NULL bo i tak w sumie nie korzystamy z niego w build_tree
	peer->tree_root = build_tree(NULL, peer->nc, &peer->tree);
	

	data_buffer_len = peer->chunk_size + 1 + 4 + 4 + 8 + 4;  // naglowek 1+4+4+8: rfc 8.6, +4 - bo channel id jeszcze
	data_buffer = malloc(data_buffer_len);
	
	// posix_fallocate()?
	
	// polacz nazwy "download" i faktyczna nazwe pliku zeby nie nadpisal nam oryginalnego pliku podczas sciagania
	sprintf(fname, "%s_%s", FILE_DOWNLOAD, peer->fname);
	
	//unlink(FILE_DOWNLOAD);
	unlink(fname);
	
	//fd = open(FILE_DOWNLOAD, O_WRONLY | O_CREAT, 0744);
	fd = open(fname, O_WRONLY | O_CREAT, 0744);
	if (fd < 0) {
		printf("error opening file '%s' for writing: %u %s\n", fname, errno, strerror(errno));
		return -1;
	}



	
	z = peer->start_chunk;
//	while (z < peer->nc) {
	while (z < peer->end_chunk) {
		
		printf("-----------z: %u  peer->end_chunk: %u\n", z, peer->end_chunk);
		begin = z;

		if (z + hashes_per_mtu >= peer->end_chunk)
			end = peer->end_chunk;
		else
			end = z + hashes_per_mtu -1 ;


		printf("begin: %lu   end: %lu\n", begin, end);
		
		// utworz tutaj REQUEST zamiast tego samego wywolania w proto_test()
		//peer->request_len = make_request(peer->request, 0xfeedbabe, peer->start_chunk, peer->end_chunk);
		peer->request_len = make_request(peer->request, 0xfeedbabe, begin, end);
		//printf("szybki dump:\n");
		//dump_request(peer->request, peer->request_len, peer);
		
		
		// wyslij requesta o dane pliku
		n = sendto(sockfd, peer->request, peer->request_len, 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
		if (n < 0) {
			printf("error sending request: %d\n", n);
			return -1;
		}
		printf("request message 3/3 sent\n");
		

		// odbierz INTEGRITY z seedera
		n = recvfrom(sockfd, (char *)buffer, BUFSIZE, 0, (struct sockaddr *) &servaddr, &len);
		if (n < 0) {
			printf("error: recvfrom: %d errno: %d %s\n", n, errno, strerror(errno));
			printf("	len: %d\n", len);
			return -1;
		}
		printf("server sent INTEGRITY: %d\n", n);
		dump_integrity(buffer, n, peer);		// tu kopiowane sa dane hashy chunkow do peer->chunk[]

		
		// skopiuj sha z tablicy chunkow do lisci drzewka
		for (x = 0; x < peer->nc; x++)
			memcpy(peer->tree[2 * x].sha, peer->chunk[x].sha, 20);
		
		
		// listuj tablice odebranych teraz chunkow
		//dump_chunk_tab(peer->chunk, peer->nc);


		
		
		
		// odbierz caly zakres chunkow od seedera
		//for (cc = peer->start_chunk; cc <= peer->end_chunk; cc++) {
		for (cc = begin; cc <= end; cc++) {
			peer->curr_chunk = cc;
			
			// odbierz pakiet danych DATA
			nr = recvfrom(sockfd, (char *)data_buffer, data_buffer_len, 0, (struct sockaddr *) &servaddr, &len);
			if (nr < 0) {
				printf("error: recvfrom: %d errno: %d %s\n", n, errno, strerror(errno));
				return -1;
			}
			//printf("server sent DATA: %d ", nr);
			//printf("server sent DATA: %d  calculated number of data: %u\n", nr, nr - (1 + 4 + 4 + 8 + 4));
			
			
			// zapisz odebrany chunk na dysku w pliku o nazwie z FILE_DOWNLOAD
			lseek(fd, cc * peer->chunk_size, SEEK_SET);
			//write(fd, data_buffer + 1 + 4 + 4 + 8 + 4, peer->chunk_size);
			write(fd, data_buffer + 1 + 4 + 4 + 8 + 4, nr - (1 + 4 + 4 + 8 + 4));
			
			// oblicz hasha
			SHA1Reset(&context);
			SHA1Input(&context, data_buffer + 1 + 4 + 4 + 8 + 4 , nr - (1 + 4 + 4 + 8 + 4));		// +1 +4 ...:przeskocz naglowek
			SHA1Result(&context, digest);
			
			// wypisz wyliczonego hasha
			s = 0;
			for (y = 0; y < 20; y++)
				s += sprintf(sha_buf + s, "%02x", digest[y] & 0xff);
			sha_buf[40] = '\0';
			//printf(" sha: %s  ", sha_buf);


			// porownaj hasha z tym ktory wyslal nam seeder w INTEGRITY
			cmp = memcmp(peer->chunk[peer->curr_chunk].sha, digest , 20);
			//printf("compare: %u ", cmp);
			
			if (cmp != 0) {		// 0= ok, hashe sa zgodne
				printf("error - hashes are different\n");
				return -1;
			}

			
			// utworz komunikat ACK potwierdzajacy ze dane zostaly odebrane od seedera i hashe sie zgadzaja - czyli akceptujemy ten pakiet danych
			//ack_len = make_ack(buffer, peer, req);
			ack_len = make_ack(buffer, peer);
			
			// wyslij tego ACK-a
			n = sendto(sockfd, buffer, ack_len, 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
			if (n < 0) {
				printf("error sending request: %d\n", n);
				return -1;
			}
			//printf("ACK[%u] sent\n" ,cc);
			//printf("server sent DATA: %d  sha: %s  compare: %u  ACK[%u] sent\n", nr, sha_buf, cmp, cc);
			
		}
		
		z += hashes_per_mtu;
	}
	
	
	
	free(data_buffer);
	close(sockfd);
	close(fd);
	return 0;
	
}








// pthread worker - seedera
void * seeder_worker (void *data)
{
	int n, clientlen;
	struct two_peers *tp;
	struct peer *p, *we;
	int sockfd, send_first_data;
	char *data_payload;
	//uint64_t data_payload_len;
	int data_payload_len;
	struct proto_opt_str pos;
	char opts[1024];			// bufor na zakodowane opcje
	char handshake_resp[256];
	int h_resp_len, opts_len;

	
	

	
	
	
	clientlen = sizeof(struct sockaddr_in);

	tp = (struct two_peers *)data;
	
	
	p = tp->peer;					// dane zdalnego hosta leechera ktory sie do nas laczy
	we = tp->we;					// nasze dane - czyli seedera
	sockfd = p->sockfd;
	

	printf("\n===========\nworker started\n");

	memset(&pos, 0, sizeof(struct proto_opt_str));
	memset(&opts, 0, sizeof(opts));


	// prepare structure as a set of parameters to make_handshake_options() proc
	pos.version = 1;
	pos.minimum_version = 1;
#warning FIXME ustawianie swarm_id
	//pos.swarm_id_len = strlen(swarm_id);
	//pos.swarm_id = swarm_id;
	pos.content_prot_method = 1;			// merkle hash tree
	pos.merkle_hash_func = 0;			// 0 = sha-1
	pos.live_signature_alg = 0;			// trzeba wziac jakas wartosc z dnssec
	pos.chunk_addr_method = 2;			// 2 = 32 bit chunk ranges
	*(unsigned int *)pos.live_disc_wind = 0x12345678;		// 32 bitowa wartosc - ale chyba trzbe ja przekodowac? albo raczej w make_handshake_options()
	pos.supported_msgs_len = 2;			// przykladowo 2 bajty mapy bitowej obslugiwanych komend
	*(unsigned int *)pos.supported_msgs = 0xffff;			// mapa bitowa: obslugujemy wszystkie komendy rfc
	pos.chunk_size = we->chunk_size;
	pos.file_size = we->file_size;
	pos.file_name_len = we->fname_len;
	memset(pos.file_name, 0, sizeof(pos.file_name));
	memcpy(pos.file_name, we->fname, we->fname_len);
	
	//printf("\n\npeerfname: %s----------------------------------\n", peer->fname);
	//sleep(10);
	
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

	pos.opt_map |= (1 << FILE_SIZE);
	pos.opt_map |= (1 << FILE_NAME);
	


	opts_len = make_handshake_options(opts, &pos);
	dump_options(opts, we);
	
	
//	printf("------------SEEDER------\n");begin: 73   end: 145

//	printf("fname: %s\n", we->fname);
	
	
	
	
	//printf("\n\nresponse handshake (have):\n");
	// make response HANDSHAKE with 0-10 chunks available
	//printf("+++++++start: %u  end: %u\n", p->start_chunk, p->end_chunk);
	//h_resp_len = make_handshake_have(handshake_resp, 0, 0xfeedbabe, opts, opts_len, peer->start_chunk, peer->end_chunk);		// tu poprawic channel id
	h_resp_len = make_handshake_have(handshake_resp, 0, 0xfeedbabe, opts, opts_len, we);		// tu poprawic channel id
	//if (peer->type == SEEDER)
	



	
	
	

	we->state = BUSY;

	//printf("MALLOCCCCCCCCCCCCCCCCCCCCCCC_p: %u\n", p->chunk_size + 1 + 4 + 4 + 8);
	//printf("MALLOCCCCCCCCCCCCCCCCCCCCCCC_we: %u\n", we->chunk_size + 1 + 4 + 4 + 8);
	//data_payload = malloc(p->chunk_size + 1 + 4 + 4 + 8);	//  chunksize + naglowki data: 1 + 4+ 4+ 8: rfc 8.6.
	data_payload = malloc(we->chunk_size + 1 + 4 + 4 + 8);	//  chunksize + naglowki data: 1 + 4+ 4+ 8: rfc 8.6.

	send_first_data = 0;	
	while (1) {
		//printf("while-------- %u  rcvlen: %u\n", message_type(p->recv_buf), p->recv_len);
		//printf("state: %u\n", we->state);
		
#if 1
		if (we->state == READY) {
			//printf("READY\n");
			//sleep(1);
			//usleep(1000);
			continue;
		}
#endif


		
//		if (message_type(p->recv_buf) == HANDSHAKE) {
		if ((message_type(p->recv_buf) == HANDSHAKE) && (p->recv_len > 0)) {
			printf("  th: -----------jestem w handshake\n");
			// pokaz odebrany 1-szy handshake
			dump_handshake_request(p->recv_buf, p->recv_len, p);

			// odeslij HANDSHAKE 2/3 + HAVE
			//n = sendto(sockfd, p->handshake_resp, p->handshake_resp_len, 0, (struct sockaddr *) &p->sa, clientlen);
			n = sendto(sockfd, handshake_resp, h_resp_len, 0, (struct sockaddr *) &p->sa, clientlen);
			if (n < 0)
				printf("ERROR in sendto");
			
			printf("  th: wyslane dane have: %u----------------------\n", n);
			//p->recv_len = 0;
			
			memset(p->fname, 0, sizeof(p->fname));
			memcpy(p->fname, we->fname, we->fname_len);
			p->chunk_size = we->chunk_size;
			//p->start_chunk = we->start_chunk;
			//p->end_chunk = we->end_chunk;
			//p->curr_chunk = p->start_chunk;		// ustaw poczatkowy numer chunka dla DATA0

			printf("  th: pchunksize:------------%u\n", p->chunk_size);
			//abort();
			//p->recv_len = 0;
			
			we->state = READY;
		}
		
		
		
		// jesli to REQUEST - wyslij INTEGRITY i zaraz za nim DATA0
		// a potem kolejne DATA1, DATA2...DATAn beda juz wysylane po ACK-u
		if (message_type(p->recv_buf) == REQUEST) {
			// odbierz REQUEST (handshake 3/3)
			
			printf("REQ\n");
			//if (p->recv_len == 0) abort();
			//if (raz >= 2) abort();
			//raz++;
			
			// pokaz odebrany request
			dump_request(p->recv_buf, n, p);
			
			
			//printf("WWWWWWWEEEEEEEEEEEE: start: %u end: %u\n", we->start_chunk, we->end_chunk);
			printf("PPPPPPPPPPPPPPPPPPP: start: %u end: %u\n", p->start_chunk, p->end_chunk);
			// rfc 5.6.2 - wyslij najpierw INTEGRITY z zadanymi hashami (0-6) a dopiero potem DATA
			n = make_integrity_v3(p->recv_buf, p, we);			// na pewno to ma byc wyslane przez recv buf? chyb tak bo to nie DATA payload
			
			
			
			// tu wyslij INTEGRITY z danymi
			n = sendto(sockfd, p->recv_buf, n, 0, (struct sockaddr *) &p->sa, clientlen);
			printf("  th: INTEGRITY sent: %u\n", n);
			
			
			//sleep(1);
			
			//p->recv_len = 0;
			
			p->curr_chunk = p->start_chunk;		// ustaw poczatkowy numer chunka dla DATA0
			send_first_data = 1;				// ustaw flage zezwolenie na wykonanie ponizej wyslania DATA0
			we->state = READY;
		}
		

		
		
//		if ((message_type(p->recv_buf) == ACK) || (send_first_data == 1)) {
//		if (((message_type(p->recv_buf) == ACK) && (p->recv_len > 0)) || (send_first_data == 1)) {
		if (((message_type(p->recv_buf) == ACK) && (p->curr_chunk <= p->end_chunk)) || (send_first_data == 1)) {
			
						 
			
			memset(data_payload, 0, data_payload_len);
			//data_payload_len = make_data(data_payload, peer, req);
			data_payload_len = make_data(data_payload, p);
			
			// teraz wyslij osobny datagram z DATA 0
			n = sendto(sockfd, data_payload, data_payload_len, 0, (struct sockaddr *) &p->sa, clientlen);
			printf("  th: DATA[%lu] sent: %d (status: %d %s)  pay_len: %d\n", p->curr_chunk, n, errno, strerror(errno), data_payload_len);
			
			
			if (message_type(p->recv_buf) == ACK) {
				// pokaz odebrany ACK
				dump_ack(p->recv_buf, p->recv_len, p);
			}
			
		
			printf("  th: curr_chunk: %lu+++++++++++++++++++\n", p->curr_chunk);
#if 0
			if (p->curr_chunk == 73) {
				printf("messagetype: %u   sendfirstdata: %u\n", message_type(p->recv_buf), send_first_data);
				abort();
			}
#endif
			p->curr_chunk++;

//			if (p->curr_chunk > p->end_chunk) abort();

			//	we->state = READY;

			//p->recv_len = 0;
			memset(p->recv_buf, 0, p->recv_len);
			//usleep(200000);
			
			send_first_data = 0;
			we->state = READY;
			
		}
		
		
		if ((message_type(p->recv_buf) == ACK) && (p->curr_chunk > p->end_chunk)) {
			//sleep(1);
			printf("xxx - workaround\n");
			
			//abort();
			we->state = READY;
		}
		
		
		
		
		//we->state = READY;		//tymczaosow!
		

		
	//	break;  			//tymczasowo!
	}
	
	
	
	// free(data_payload)
}















// serwer - udostepnia podany w command line plik
// wersja uzywajaca pthread-y
int net_seeder_v3(struct peer *seeder)
{
	int sockfd;
	int portno;
	socklen_t clientlen;
	struct sockaddr_in serveraddr;
	struct sockaddr_in clientaddr;
	//struct hostent *hostp;
	char buf[BUFSIZE];
	//char *hostaddrp;
	int optval, n;
	char *data_payload;
	struct peer *p;
	pthread_t thread;
	struct two_peers tp;
	int st;
	uint64_t cnt = 0;

	portno = PORT;

	
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
		printf("ERROR opening socket");

	optval = 1;
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int));

	bzero((char *) &serveraddr, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
	serveraddr.sin_port = htons((unsigned short)portno);

	if (bind(sockfd, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0)
		printf("ERROR on binding");

	clientlen = sizeof(clientaddr);

	
	
	
	data_payload = malloc(seeder->chunk_size + 1 + 4 + 4 + 8);	//  chunksize + naglowki data: 1 + 4+ 4+ 8: rfc 8.6.

	//data_already_received = 0;
	while (1) {
		// odbierz HANDSHAKE lub REQUEST
		bzero(buf, BUFSIZE);
		n = recvfrom(sockfd, buf, BUFSIZE, 0, (struct sockaddr *) &clientaddr, &clientlen);
		if (n < 0)
			printf("ERROR in recvfrom");
		

		if (message_type(buf) == HANDSHAKE) {
			p = new_peer(&clientaddr, BUFSIZE, sockfd);
			printf("clientlen: %u\n", clientlen);
			printf("%s:%u\n", inet_ntoa(clientaddr.sin_addr), ntohs(clientaddr.sin_port));

			memcpy(p->recv_buf, buf, n);
			p->recv_len = n;

			// utworz nowy watek
			
			//tp.we = &we_local;
			tp.we = seeder;
			tp.peer = p;
			seeder->state = BUSY;
			st = pthread_create(&thread, NULL, &seeder_worker, &tp);
			
		}
		
		
		if (message_type(buf) == REQUEST) {
			printf("OK REQUEST\n");
			
			// zaczekaj az seeder->state bedzie READY
			cnt = 0;
			while (seeder->state != READY) cnt++;
			printf("spinlock request: %lu\n", cnt);
			
			//tu spr czy worker jest READY - jak nie to zwroc CHOKE leecherowi - ale to pozniej
			memcpy(p->recv_buf, buf, n);
			p->recv_len = n;
			// tu zalaczyc jakie zezwolenie / wlaczenie workera - zeby przetworzyl ten request
			seeder->state = BUSY;

			
		}
		
		
		if (message_type(buf) == ACK) {
			printf("OK ACK\n");
			//tu spr czy worker jest READY - jak nie to zwroc CHOKE leecherowi - ale to pozniej

			// zaczekaj az seeder->state bedzie READY
			cnt = 0;
			while (seeder->state != READY) cnt++;
			printf("spinlock ACK: %lu\n", cnt);
			//if (cnt > 0) abort();
				
			memcpy(p->recv_buf, buf, n);
			p->recv_len = n;
			// tu zalaczyc jakie zezwolenie / wlaczenie workera - zeby przetworzyl ten request
			seeder->state = BUSY;
		}
		
		
		
		
		
		
		
	}

	free(data_payload);

}







// klient - odbiorca pliku
int net_leecher_v3(struct peer *peer)
{
	int sockfd;
	char buffer[BUFSIZE];
	struct sockaddr_in servaddr;
	int n, x, s, y, fd, z, nr;
	socklen_t len;
	uint8_t *data_buffer;
	uint32_t data_buffer_len;
	SHA1Context context;
	unsigned char digest[20];
	uint8_t sha_buf[40 + 1], sha_seeder_buf[40 + 1];
	uint8_t cmp;
	uint64_t ack_len, cc;
	uint64_t num_series, hashes_per_mtu, rest, begin, end;
	char fname [256 + 32];
	
	len = sizeof(servaddr);
    
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket creation failed");
		exit(EXIT_FAILURE);
	}
  
	memset(&servaddr, 0, sizeof(servaddr));
      
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(PORT);
	servaddr.sin_addr.s_addr = inet_addr(IP);
      

	// wyslij handshake inicjujacy (pierwszy z trzech) - czyli probujemy nawiazac polaczenie z serwerem
	n = sendto(sockfd, peer->handshake_req, peer->handshake_req_len, 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
	if (n < 0) {
		printf("error sending handhsake: %d\n", n);
		return -1;
	}
	printf("initial message 1/3 sent\n");
         
	// odbierz odpowiedz serwera (handshake2) + have?
	n = recvfrom(sockfd, (char *)buffer, BUFSIZE, 0, (struct sockaddr *) &servaddr, &len);
	buffer[n] = '\0';
	printf("server replied with %u bytes\n", n);
	dump_handshake_have(buffer, n, peer);

	
	
	// oblicz ile bedzie serii i ile chunkow w jednej serii
	// ponizsza wielkosc 1500 (mtu) - moznaby sprametryzowac - np. z poziomu command line
	hashes_per_mtu = (1500 - (1 + 4 + 4 + 8 + 4))/20;		// 1+4+4+8+4: naglowek, 20-wielksoc pojedynczego hasha SHA-1
	printf("hashes_per_mtu: %lu ---------------\n", hashes_per_mtu);		// ile SHA-1 chunkow zmiesci sie w jednum MTU
	
	num_series = peer->nc / hashes_per_mtu;
	rest = peer->nc % hashes_per_mtu;
	printf("nc: %u   num_series: %lu   rest: %lu\n", peer->nc, num_series, rest);
	

	// tu chyba trzeba utworzyc drzewko o ilosci lisci peer->nl i przekopiowac tam sha z tab chunkow
	// tymczasowo zamiast pierwszego param jest NULL bo i tak w sumie nie korzystamy z niego w build_tree
	peer->tree_root = build_tree(NULL, peer->nc, &peer->tree);
	

	data_buffer_len = peer->chunk_size + 1 + 4 + 4 + 8 + 4;  // naglowek 1+4+4+8: rfc 8.6, +4 - bo channel id jeszcze
	data_buffer = malloc(data_buffer_len);
	
	// posix_fallocate()?
	
	// polacz nazwy "download" i faktyczna nazwe pliku zeby nie nadpisal nam oryginalnego pliku podczas sciagania
	sprintf(fname, "%s_%s", FILE_DOWNLOAD, peer->fname);
	
	//unlink(FILE_DOWNLOAD);
	unlink(fname);
	
	//fd = open(FILE_DOWNLOAD, O_WRONLY | O_CREAT, 0744);
	fd = open(fname, O_WRONLY | O_CREAT, 0744);
	if (fd < 0) {
		printf("error opening file '%s' for writing: %u %s\n", fname, errno, strerror(errno));
		return -1;
	}



	
	z = peer->start_chunk;
//	while (z < peer->nc) {
	while (z < peer->end_chunk) {
		
		printf("-----------z: %u  peer->end_chunk: %u\n", z, peer->end_chunk);
		begin = z;

		if (z + hashes_per_mtu >= peer->end_chunk)
			end = peer->end_chunk;
		else
			end = z + hashes_per_mtu -1 ;


		printf("begin: %lu   end: %lu\n", begin, end);
		
		// utworz tutaj REQUEST zamiast tego samego wywolania w proto_test()
		//peer->request_len = make_request(peer->request, 0xfeedbabe, peer->start_chunk, peer->end_chunk);
		peer->request_len = make_request(peer->request, 0xfeedbabe, begin, end);
		//printf("szybki dump:\n");
		//dump_request(peer->request, peer->request_len, peer);
		
		
		// wyslij requesta o dane pliku
		n = sendto(sockfd, peer->request, peer->request_len, 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
		if (n < 0) {
			printf("error sending request: %d\n", n);
			return -1;
		}
		printf("request message 3/3 sent\n");
		

		// odbierz INTEGRITY z seedera
		n = recvfrom(sockfd, (char *)buffer, BUFSIZE, 0, (struct sockaddr *) &servaddr, &len);
		if (n < 0) {
			printf("error: recvfrom: %d errno: %d %s\n", n, errno, strerror(errno));
			printf("	len: %d\n", len);
			return -1;
		}
		printf("server sent INTEGRITY: %d\n", n);
		dump_integrity(buffer, n, peer);		// tu kopiowane sa dane hashy chunkow do peer->chunk[]

#warning FIXME tu nie powinno byc for 0...peer->nc 
		// skopiuj sha z tablicy chunkow do lisci drzewka
		printf("kopiowanie sha %u-%u =================================\n", 0, peer->nc);
		for (x = 0; x < peer->nc; x++)
			memcpy(peer->tree[2 * x].sha, peer->chunk[x].sha, 20);
		
		
		// listuj tablice odebranych teraz chunkow
		//dump_chunk_tab(peer->chunk, peer->nc);


		
		
		
		// odbierz caly zakres chunkow od seedera
		//for (cc = peer->start_chunk; cc <= peer->end_chunk; cc++) {
		for (cc = begin; cc <= end; cc++) {
			peer->curr_chunk = cc;
			
			// odbierz pakiet danych DATA
			nr = recvfrom(sockfd, (char *)data_buffer, data_buffer_len, 0, (struct sockaddr *) &servaddr, &len);
			if (nr < 0) {
				printf("error: recvfrom: %d errno: %d %s\n", n, errno, strerror(errno));
				return -1;
			}
			//printf("server sent DATA: %d ", nr);
			//printf("server sent DATA: %d  calculated number of data: %u\n", nr, nr - (1 + 4 + 4 + 8 + 4));
			
			
			// zapisz odebrany chunk na dysku w pliku o nazwie z FILE_DOWNLOAD
			lseek(fd, cc * peer->chunk_size, SEEK_SET);
			//write(fd, data_buffer + 1 + 4 + 4 + 8 + 4, peer->chunk_size);
			write(fd, data_buffer + 1 + 4 + 4 + 8 + 4, nr - (1 + 4 + 4 + 8 + 4));
			
			// oblicz hasha
			SHA1Reset(&context);
			//SHA1Input(&context, data_buffer + 1 + 4 + 4 + 8 + 4 , peer->chunk_size);		// +1 +4 ...:przeskocz naglowek
			SHA1Input(&context, data_buffer + 1 + 4 + 4 + 8 + 4 , nr - (1 + 4 + 4 + 8 + 4));		// +1 +4 ...:przeskocz naglowek
			SHA1Result(&context, digest);
			
			// wypisz wyliczonego hasha
			s = 0;
			for (y = 0; y < 20; y++)
				s += sprintf((char *)(sha_buf + s), "%02x", digest[y] & 0xff);
			sha_buf[40] = '\0';
			//printf(" calculated sha (digest): %s  ", sha_buf);
		
			// konwertuj na ASCII odebrany z seedera
			s = 0;
			for (y = 0; y < 20; y++)
				s += sprintf((char *)(sha_seeder_buf + s), "%02x", peer->chunk[peer->curr_chunk].sha[y] & 0xff);
			sha_seeder_buf[40] = '\0';
			
		
		

			// porownaj hasha z tym ktory wyslal nam seeder w INTEGRITY
			cmp = memcmp(peer->chunk[peer->curr_chunk].sha, digest , 20);
			//printf("compare: %u ", cmp);
			
			if (cmp != 0) {		// 0= ok, hashe sa zgodne
				printf("error - hashes are different[%lu]: seeder %s vs digest: %s\n", cc, sha_seeder_buf, sha_buf);
				//while(1) sleep(1);
				abort();
				//return -1;
			} else printf("ok, hashes are ok[%lu]: %s %s\n", cc, sha_seeder_buf, sha_buf);

			
			// utworz komunikat ACK potwierdzajacy ze dane zostaly odebrane od seedera i hashe sie zgadzaja - czyli akceptujemy ten pakiet danych
			//ack_len = make_ack(buffer, peer, req);
			ack_len = make_ack(buffer, peer);
			
			// wyslij tego ACK-a
			n = sendto(sockfd, buffer, ack_len, 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
			if (n < 0) {
				printf("error sending request: %d\n", n);
				return -1;
			}
			//printf("ACK[%lu] sent\n" ,cc);
			printf("ACK[%lu] sent\n" ,cc);
			//printf("server sent DATA: %d  sha: %s  compare: %u  ACK[%u] sent\n", nr, sha_buf, cmp, cc);
			
		}
		
		z += hashes_per_mtu;
	}
	
	
	
	free(data_buffer);
	close(sockfd);
	close(fd);
	return 0;
	
}


















int net_seeder(struct peer *peer)
{
//	net_seeder_v2(peer);
	net_seeder_v3(peer);
	
	return 0;
}




int net_leecher(struct peer *peer)
{
//	net_leecher_v2(peer);
	net_leecher_v3(peer);
	
	return 0;
}





