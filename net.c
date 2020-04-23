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



// serwer - udostepnia podany w command line plik
int net_seeder_v2(struct peer *peer, struct req *req)
{
	int sockfd;
	int portno;
	int clientlen;
	struct sockaddr_in serveraddr;
	struct sockaddr_in clientaddr;
	struct hostent *hostp;
	char buf[BUFSIZE];
	char *hostaddrp;
	int optval;
	int n;
	char *data_payload;
	u32 data_payload_len, cc;

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

	while (1) {
		bzero(buf, BUFSIZE);
		
		// odbierz HANDSHAKE
		n = recvfrom(sockfd, buf, BUFSIZE, 0, (struct sockaddr *) &clientaddr, &clientlen);
		if (n < 0)
			printf("ERROR in recvfrom");

		// kto wyslal datagram
		hostp = gethostbyaddr((const char *)&clientaddr.sin_addr.s_addr, sizeof(clientaddr.sin_addr.s_addr), AF_INET);
		if (hostp == NULL) {
			printf("ERROR on gethostbyaddr");
			printf("herrno: %d\n", h_errno);
		}
		hostaddrp = inet_ntoa(clientaddr.sin_addr);
		if (hostaddrp == NULL)
			printf("ERROR on inet_ntoa\n");
		printf("server received datagram from %s (%s)\n", hostp->h_name, hostaddrp);
		printf("server received %d bytes: %s\n", n, buf);
		// pokaz odebrany 1-szy handshake
		dump_handshake_request(buf, n, peer);
		

		
		// odeslij HANDSHAKE 2/3 + HAVE
		n = sendto(sockfd, peer->handshake_resp, peer->handshake_resp_len, 0, (struct sockaddr *) &clientaddr, clientlen);
		if (n < 0)
			printf("ERROR in sendto");
		
		
		
		data_payload = malloc(peer->chunk_size + 1 + 4 + 4 + 8);	//  chunksize + naglowki data: 1 + 4+ 4+ 8: rfc 8.6.
		
		
		while (1) {	
			// odbierz REQUEST (handshake 3/3)
			bzero(buf, BUFSIZE);
			n = recvfrom(sockfd, buf, BUFSIZE, 0, (struct sockaddr *) &clientaddr, &clientlen);
			// pokaz odebrany request
			dump_request(buf, n, peer);
			
			
			// rfc 5.6.2 
			// wyslij najpierw INTEGRITY z zadanymi hashami (0-6) a dopiero potem DATA - oba komunikaty maga byc w jednym datagramie
			n = make_integrity(buf, peer);
			
			// tu wyslij INTEGRITY z danymi
			n = sendto(sockfd, buf, n, 0, (struct sockaddr *) &clientaddr, clientlen);
			printf("INTEGRITY sent: %u\n", n);

			
			// utworz pakiet DATA z danymi chunka o numerze req->curr_chunk
			
			//req->curr_chunk = peer->start_chunk;
			
			for (cc = peer->start_chunk; cc <= peer->end_chunk; cc++) {
				req->curr_chunk = cc;
				data_payload_len = make_data(data_payload, peer, req);
				
				// teraz wyslij osobny datagram z DATA 0
				n = sendto(sockfd, data_payload, data_payload_len, 0, (struct sockaddr *) &clientaddr, clientlen);
				printf("DATA[%u] sent: %d (status: %d %s)\n", cc, n, errno, strerror(errno));
				
					
				// odbierz ACK
				bzero(buf, BUFSIZE);
				n = recvfrom(sockfd, buf, BUFSIZE, 0, (struct sockaddr *) &clientaddr, &clientlen);
				// pokaz odebrany ACK
				dump_ack(buf, n, peer);
			}
		}
		
		
		free(data_payload);
		
	}
}







// klient - odbiorca pliku
int net_leecher_v2(struct peer *peer, struct req *req)
{
	int sockfd;
	char buffer[BUFSIZE];
	struct sockaddr_in servaddr;
	int n, len, x, s, y, fd, z, nr;
	char *data_buffer;
	u32 data_buffer_len;
	SHA1Context context;
	unsigned char digest[20], sha_buf[40 + 1];
	u8 cmp;
	u32 ack_len, cc;
	u32 num_series, hashes_per_mtu, rest, begin, end;
	
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
	printf("hashes_per_mtu: %u ---------------\n", hashes_per_mtu);		// ile SHA-1 chunkow zmiesci sie w jednum MTU
	
	num_series = peer->nc / hashes_per_mtu;
	rest = peer->nc % hashes_per_mtu;
	printf("nc: %u   num_series: %u   rest: %u\n", peer->nc, num_series, rest);
	

	// tu chyba trzeba utworzyc drzewko o ilosci lisci peer->nl i przekopiowac tam sha z tab chunkow
	// tymczasowo zamiast pierwszego param jest NULL bo i tak w sumie nie korzystamy z niego w build_tree
	peer->tree_root = build_tree(NULL, peer->nc, &peer->tree);
	

	data_buffer_len = peer->chunk_size + 1 + 4 + 4 + 8 + 4;  // naglowek 1+4+4+8: rfc 8.6, +4 - bo channel id jeszcze
	data_buffer = malloc(data_buffer_len);
	
	// posix_fallocate()?
	
	unlink(FILE_DOWNLOAD);
	
	fd = open(FILE_DOWNLOAD, O_WRONLY | O_CREAT, 0744);
	if (fd < 0) {
		printf("error opening file '%s' for writing: %u %s\n", FILE_DOWNLOAD, errno, strerror(errno));
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


		printf("begin: %u   end: %u\n", begin, end);
		
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
			req->curr_chunk = cc;
			
			// odbierz pakiet danych DATA
			nr = recvfrom(sockfd, (char *)data_buffer, data_buffer_len, 0, (struct sockaddr *) &servaddr, &len);
			if (nr < 0) {
				printf("error: recvfrom: %d errno: %d %s\n", n, errno, strerror(errno));
				return -1;
			}
			//printf("server sent DATA: %d ", nr);
		
			// zapisz odebrany chunk na dysku w pliku o nazwie z FILE_DOWNLOAD
			lseek(fd, cc * peer->chunk_size, SEEK_SET);
			write(fd, data_buffer + 1 + 4 + 4 + 8 + 4, peer->chunk_size);
			
			// oblicz hasha
			SHA1Reset(&context);
			SHA1Input(&context, data_buffer + 1 + 4 + 4 + 8 + 4 , peer->chunk_size);		// +1 +4 ...:przeskocz naglowek
			SHA1Result(&context, digest);
			
			// wypisz wyliczonego hasha
			s = 0;
			for (y = 0; y < 20; y++)
				s += sprintf(sha_buf + s, "%02x", digest[y] & 0xff);
			sha_buf[40] = '\0';
			//printf(" sha: %s  ", sha_buf);


			// porownaj hasha z tym ktory wyslal nam seeder w INTEGRITY
			cmp = memcmp(peer->chunk[req->curr_chunk].sha, digest , 20);
			//printf("compare: %u ", cmp);
			
			if (cmp != 0) {		// 0= ok, hashe sa zgodne
				printf("error - hashes are different\n");
				return -1;
			}

			
			// utworz komunikat ACK potwierdzajacy ze dane zostaly odebrane od seedera i hashe sie zgadzaja - czyli akceptujemy ten pakiet danych
			ack_len = make_ack(buffer, peer, req);
			
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









int net_seeder(struct peer *peer, struct req *req)
{
//	net_seeder_v1(peer, req);
	net_seeder_v2(peer, req);
}




int net_leecher(struct peer *peer, struct req *req)
{
//	net_leecher_v1(peer, req);
	net_leecher_v2(peer, req);
}





