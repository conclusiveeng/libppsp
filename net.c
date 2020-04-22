#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "mt.h"
#include "net.h"
#include "ppspp_protocol.h"
#include "peer.h"

#define BUFSIZE 1024
#define PORT     6778

#define IP "127.0.0.1"
//#define IP "192.168.1.64"

extern int h_errno;


// serwer - udostepnia podany w command line plik
int net_seeder(struct peer *peer)
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
//		n = sendto(sockfd, handshake2, handshake2_len, 0, (struct sockaddr *) &clientaddr, clientlen);
		n = sendto(sockfd, peer->handshake_resp, peer->handshake_resp_len, 0, (struct sockaddr *) &clientaddr, clientlen);
		if (n < 0)
			printf("ERROR in sendto");
		
		
		
		
		// odbierz REQUEST (handshake 3/3)
		bzero(buf, BUFSIZE);
		n = recvfrom(sockfd, buf, BUFSIZE, 0, (struct sockaddr *) &clientaddr, &clientlen);
		// pokaz odebrany request
		dump_request(buf, n);
		
		
		// rfc 5.6.2 
		// wyslij najpierw INTEGRITY z zadanymi hashami (0-6) a dopiero potem DATA - oba komunikaty maga byc w jednym datagramie
		n = make_integrity(buf, peer);
		
		// tu wyslij INTEGRITY z danymi
		n = sendto(sockfd, buf, n, 0, (struct sockaddr *) &clientaddr, clientlen);
		printf("INTEGRITY sent: %u\n", n);
		
		
		
	}
}


// klient - odbiorca pliku
int net_leecher(struct peer *peer)
{
	int sockfd;
	char buffer[BUFSIZE];
	struct sockaddr_in servaddr;
	int n, len;
    
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket creation failed");
		exit(EXIT_FAILURE);
	}
  
	memset(&servaddr, 0, sizeof(servaddr));
      
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(PORT);
	servaddr.sin_addr.s_addr = inet_addr(IP);
      

	// wyslij handshake inicjujacy (pierwszy z trzech) - czyli probujemy nawiazac polaczenie z serwerem
	sendto(sockfd, peer->handshake_req, peer->handshake_req_len, MSG_CONFIRM, (const struct sockaddr *) &servaddr, sizeof(servaddr));
	
	printf("initial message 1/3 sent\n");
         
	// odbierz odpowiedz serwera (handshake2)
	n = recvfrom(sockfd, (char *)buffer, BUFSIZE, MSG_WAITALL, (struct sockaddr *) &servaddr, &len);
	buffer[n] = '\0';
	printf("server replied with %u bytes\n", n);
	dump_handshake_response(buffer, n, peer);

	
	// uwtorz tutaj REQUEST zamiast tego samego wywolania w proto_test()

	peer->request_len = make_request(peer->request, 0xfeedbabe, peer->start_chunk, peer->end_chunk);
	//printf("szybki dump:\n");
	//dump_request(peer->request, peer->request_len);
	
	
	// wyslij requesta o dane pliku
	sendto(sockfd, peer->request, peer->request_len, MSG_CONFIRM, (const struct sockaddr *) &servaddr, sizeof(servaddr));
	printf("request message 3/3 sent\n");
	
	
	// odbierz INTEGRITY z seedera
	n = recvfrom(sockfd, (char *)buffer, BUFSIZE, MSG_WAITALL, (struct sockaddr *) &servaddr, &len);
	printf("server sent INTEGRITY: %u\n", n);
	dump_integrity(buffer, n, peer);
	
	
	
	close(sockfd);
	return 0;
	
}

