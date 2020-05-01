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
#include <semaphore.h>

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
#define SEM_NAME "/ppspp"

extern int h_errno;






int16_t ip_port_to_idx (struct sockaddr_in *client)
{
	int16_t x, ret;
	
	ret = -1;
	for (x = 0; x < num_threads; x++) {
		if (memcmp(&threads[x].sa, client, sizeof(struct sockaddr_in)) == 0) {
			ret = x;
		}
	}

	return ret;
}


sem_t * semaph_init (struct peer *p)
{
	sem_t *sem;

	memset(p->sem_name, 0, sizeof(p->sem_name));
	snprintf(p->sem_name, sizeof(p->sem_name) - 1, "%s_%lx_%lx", SEM_NAME, getpid(), random());

	sem_unlink(p->sem_name);
	
	sem = sem_open(p->sem_name, O_CREAT | O_RDWR, 0777, 0);		/* create semaphore initially locked */
	if (sem == SEM_FAILED) {
		printf("sem_open error: %s\n", strerror(errno));
		abort();
	}

	return sem;
}


int semaph_post (sem_t *sem)
{
	int s;

	s = sem_post(sem);
	if (s != 0) {
		printf("%s: error: %u  %s\n", __FUNCTION__, errno, strerror(errno));
		abort();
	}
	
	return 0;
}


int semaph_wait (sem_t *sem)
{
	int s;

	s = sem_wait(sem);
	if (s != 0) {
		printf("%s: error: %u  %s\n", __FUNCTION__, errno, strerror(errno));
		abort();
	}

	return 0;
}


void * diagnostic (void *data)
{
	int x;
	struct timespec ts;

	while (1) {
		printf("\n\n--------------------------------------------------DIAGNOSTICS--------------------------------------------\n\n");
		printf("not active: ");
		for (x = 0; x < num_threads; x++) {
			clock_gettime(CLOCK_MONOTONIC, &ts);
			if (ts.tv_sec - threads[x].peer->ts_last_recv.tv_sec > 1) {
				printf("[%u] ", x);
			}
		}
		printf("\n");
		sleep(1);
	}
}


/* thread - seeder worker */
void * seeder_worker (void *data)
{
	int n, clientlen;
	struct two_peers *tp;
	struct peer *p, *we;
	int sockfd;
	char *data_payload;
	int data_payload_len;
	struct proto_opt_str pos;
	char opts[1024];			/* buffer for encoded options */
	char handshake_resp[256];
	int h_resp_len, opts_len;
	
	

	clientlen = sizeof(struct sockaddr_in);

	tp = (struct two_peers *)data;
	p = tp->peer;					/* data of remote host (leecher) connecting to us (seeder)*/
	we = tp->we;					/* our data (seeder) */
	sockfd = p->sockfd;
	

	printf("\n  th: ===========\n  th: worker started\n");

	memset(&pos, 0, sizeof(struct proto_opt_str));
	memset(&opts, 0, sizeof(opts));


	/* prepare structure as a set of parameters to make_handshake_options() proc */
	pos.version = 1;
	pos.minimum_version = 1;
#warning FIXME ustawianie swarm_id
	//pos.swarm_id_len = strlen(swarm_id);
	//pos.swarm_id = swarm_id;
	pos.content_prot_method = 1;			/* merkle hash tree */
	pos.merkle_hash_func = 0;			/* 0 = sha-1 */
	pos.live_signature_alg = 0;			/* should be taken from DNSSEC */
	pos.chunk_addr_method = 2;			/* 2 = 32 bit chunk ranges */
	*(unsigned int *)pos.live_disc_wind = 0x12345678;
	pos.supported_msgs_len = 2;			/* bitmap of supported messages consists of 2 bytes */
	*(unsigned int *)pos.supported_msgs = 0xffff;	/* bitmap of supported messages */
	pos.chunk_size = we->chunk_size;
	pos.file_size = we->file_size;
	pos.file_name_len = we->fname_len;
	memset(pos.file_name, 0, sizeof(pos.file_name));
	memcpy(pos.file_name, we->fname, we->fname_len);
	
	
	/* mark the options we want to pass to make_handshake_options() (which ones are valid) */
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
	if (opts_len > 1024) {
		printf("opts_len: %u > 1024\n", opts_len);
		abort();
	}
	dump_options(opts, we);
	
	h_resp_len = make_handshake_have(handshake_resp, 0, 0xfeedbabe, opts, opts_len, we);
	if (h_resp_len > 256) {
		printf("h_resp_len (%u) > 256\n", h_resp_len);
		abort();
	}
	
	
	
	p->sm = SM_NONE;
	p->finished = 0;
	
	data_payload = malloc(we->chunk_size + 4 + 1 + 4 + 4 + 8);	/* chunksize + headers */

	while (p->finishing == 0) {
		semaph_wait(p->sem);

		if ((p->sm == SM_NONE) && (message_type(p->recv_buf) == HANDSHAKE) && (p->recv_len > 0)) 
			p->sm = SM_HANDSHAKE_INIT;

		if (p->sm == SM_HANDSHAKE_INIT) {
			clock_gettime(CLOCK_MONOTONIC, &p->ts_last_recv);
			p->d_last_recv = HANDSHAKE;

			dump_handshake_request(p->recv_buf, p->recv_len, p);

			p->sm = SM_HANDSHAKE_HAVE;
			semaph_post(p->sem);
			continue;
		}

		if (p->sm == SM_HANDSHAKE_HAVE) {
			if (p->recv_len == 0)  abort();
			/* send HANDSHAKE + HAVE */
			n = sendto(sockfd, handshake_resp, h_resp_len, 0, (struct sockaddr *) &p->sa, clientlen);
			if (n < 0) {
				printf("ERROR in sendto\n");
				abort();
			}
			
			clock_gettime(CLOCK_MONOTONIC, &p->ts_last_send);
			p->d_last_send = HAVE;
			
			if (we->fname_len > sizeof(p->fname))  abort();
			memset(p->fname, 0, sizeof(p->fname));
			memcpy(p->fname, we->fname, we->fname_len);
			p->chunk_size = we->chunk_size;
			p->recv_len = 0;
			p->sm = SM_WAIT_REQUEST;

			semaph_post(p->sem);
			continue;
		}

		if (p->sm == SM_WAIT_REQUEST) {
			if ((message_type(p->recv_buf) == REQUEST) && (p->recv_len > 0)) 
				p->sm = SM_REQUEST;

			semaph_post(p->sem);
			continue;
		}

		if (p->sm == SM_REQUEST) {
			if (p->recv_len == 0) {
				printf("recv_len==0\n");
				abort();
			}

			clock_gettime(CLOCK_MONOTONIC, &p->ts_last_recv);
			p->d_last_recv = REQUEST;
			
			printf("REQ\n");

			dump_request(p->recv_buf, n, p);
			p->sm = SM_INTEGRITY;

			semaph_post(p->sem);
			continue;
		}

		if (p->sm == SM_INTEGRITY) {
			n = make_integrity(p->send_buf, p, we);

			if (n > BUFSIZE) abort();

			/* send INTEGRITY with data */
			n = sendto(sockfd, p->send_buf, n, 0, (struct sockaddr *) &p->sa, clientlen);
			if (n < 0) {
				printf("ERROR in sendto\n");
				abort();
			}
			
			clock_gettime(CLOCK_MONOTONIC, &p->ts_last_send);
			p->d_last_send = INTEGRITY;
			p->recv_len = 0;
			p->curr_chunk = p->start_chunk;		/* set beginning number of chunk for DATA0 */
			p->sm = SM_DATA;

			semaph_post(p->sem);
			continue;
		}

		if (p->sm == SM_DATA) {
			clock_gettime(CLOCK_MONOTONIC, &p->ts_last_recv);

			data_payload_len = make_data(data_payload, p);
			
			if (data_payload_len > we->chunk_size + 4 + 1 + 4 + 4 + 8) {
				printf("datapayloadlen: %u    allocated: %u\n", data_payload_len, we->chunk_size + 4 + 1 + 4 + 4 + 8 );
				abort();
			}
		
			/* send DATA datagram with contents of the chunk */
			n = sendto(sockfd, data_payload, data_payload_len, 0, (struct sockaddr *) &p->sa, clientlen);
			if (n < 0) {
				printf("ERROR in sendto\n");
				abort();
			}

			clock_gettime(CLOCK_MONOTONIC, &p->ts_last_send);
			p->d_last_send = DATA;
			p->sm = SM_WAIT_ACK;

			semaph_post(p->sem);
			continue;
		}

		if (p->sm == SM_WAIT_ACK)	{
			if (message_type(p->recv_buf) == ACK) 
				p->sm = SM_ACK;

			semaph_post(p->sem);
			continue;
		}

		if (p->sm == SM_ACK) {
			dump_ack(p->recv_buf, p->recv_len, p);

			p->curr_chunk++;
			p->recv_len = 0;

			if (p->curr_chunk <= p->end_chunk)		/* if this is not ACK for our last sent DATA then go to DATA state */
				p->sm = SM_DATA;
			else if (p->curr_chunk > p->end_chunk)		
				p->sm = SM_WAIT_REQUEST;		/* that was ACK for last DATA in serie so wait for REQUEST */
				
			semaph_post(p->sem);
			continue;
		}
	}

	/* finishing thread */

	free(data_payload);


	p->finished = 1;

	pthread_exit(NULL);
}






/* UDP datagram server (SEEDER) */
int net_seeder(struct peer *seeder)
{
	int sockfd;
	int portno;
	socklen_t clientlen;
	struct sockaddr_in serveraddr;
	struct sockaddr_in clientaddr;
	char buf[BUFSIZE];
	int optval, n;
	struct peer *p;
	pthread_t thread;
	struct two_peers tp[16];			// tyle samo ile max moze byc watkow
	int st;
	uint64_t cnt = 0;
	int16_t th_idx;
	int sval;

	portno = PORT;


	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
		printf("ERROR opening socket\n");

	optval = 1;
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int));

	bzero((char *) &serveraddr, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
	serveraddr.sin_port = htons((unsigned short)portno);

	if (bind(sockfd, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0)
		printf("ERROR on binding\n");

	clientlen = sizeof(clientaddr);

	num_threads = 0;
	
	
	
	/* diagnostic thread */
	/* th_diag = pthread_create(&th_diag, NULL, &diagnostic, NULL); */
	
	
	while (1) {
		bzero(buf, BUFSIZE);
		n = recvfrom(sockfd, buf, BUFSIZE, 0, (struct sockaddr *) &clientaddr, &clientlen);
		if (n < 0)
			printf("ERROR in recvfrom\n");

		th_idx = ip_port_to_idx(&clientaddr);
		if (th_idx < 0) {
			printf("nie znaleziono------------------------\n");
			p = NULL;
		} else {
			p = threads[th_idx].peer;
		}

		if (message_type(buf) == HANDSHAKE) {
			printf("OK HANDSHAKE\n");
			if (handshake_type(buf) == HANDSHAKE_INIT) {

				if (num_threads > 4) {
					printf("too many threads: %u\n", num_threads);
					//abort();
					exit(1);
				}

				p = new_peer(&clientaddr, BUFSIZE, sockfd);

				if (n > BUFSIZE) abort();

				memcpy(p->recv_buf, buf, n);
				p->recv_len = n;

				tp[num_threads].we = seeder;
				tp[num_threads].peer = p;
				/* create new semaphore */
				p->sem = semaph_init(p);

				/* create worker thread for this client (leecher) */
				st = pthread_create(&thread, NULL, &seeder_worker, &tp[num_threads]);
				
				printf("new pthread created[%u]: %#lx\n", num_threads, thread);
				
				threads[num_threads].tid = thread;
				threads[num_threads].peer = p;
				memcpy(&threads[num_threads].sa, &clientaddr, sizeof(struct sockaddr_in));
				num_threads++;
				semaph_post(p->sem);	/* unlock initially locked semaphore */
				continue;
			} else if (handshake_type(buf) == HANDSHAKE_FINISH) {	/* does the seeder want to close connection ? */

				printf("-------------------FINISH\n");

				p->finishing = 1;	/* set the flag for finishing the thread */

				cnt = 0;
				while (p->finished == 0) cnt++;
				printf("---------pthread finished-----  cnt: %lu\n", cnt);


				/* free allocated memory */
				free(p->recv_buf);
				free(p->send_buf);
				free(p);

				/* destroy the semaphore */
				sem_unlink(p->sem_name);

				continue;
				
			}
		}


		if (message_type(buf) == REQUEST) {
			semaph_wait(p->sem);

			printf("OK REQUEST\n");


			//tu spr czy worker jest READY - jak nie to zwroc CHOKE leecherowi - ale to pozniej
			if (n > BUFSIZE) abort();
			memcpy(p->recv_buf, buf, n);
			p->recv_len = n;
			semaph_post(p->sem);
			continue;
		}
		
		if (message_type(buf) == ACK) {
			semaph_wait(p->sem);

			printf("OK ACK\n");
			if (n > BUFSIZE) abort();
			
			memcpy(p->recv_buf, buf, n);
			p->recv_len = n;
			semaph_post(p->sem);
			continue;
		}
	}
}



/*UDP datagram client - LEECHER */
int net_leecher(struct peer *peer)
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
      
	/* send initial HANDSHAKE to SEEDER */
	n = sendto(sockfd, peer->handshake_req, peer->handshake_req_len, 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
	if (n < 0) {
		printf("error sending handhsake: %d\n", n);
		//return -1;
		abort();
	}
	printf("initial message 1/3 sent\n");
         
	/* receive response from SEEDER: HANDSHAKE + HAVE */
	n = recvfrom(sockfd, (char *)buffer, BUFSIZE, 0, (struct sockaddr *) &servaddr, &len);
	buffer[n] = '\0';
	printf("server replied with %u bytes\n", n);
	dump_handshake_have(buffer, n, peer);

	/* calculate number of SHA hashes per 1500 bytes MTU */
	hashes_per_mtu = (1500 - (4 + 1 + 4 + 4 + 8))/20;
	printf("hashes_per_mtu: %lu ---------------\n", hashes_per_mtu);
	
	/* calculate number of series */
	num_series = peer->nc / hashes_per_mtu;
	rest = peer->nc % hashes_per_mtu;
	printf("nc: %u   num_series: %lu   rest: %lu\n", peer->nc, num_series, rest);

	/* build the tree */
	peer->tree_root = build_tree(peer->nc, &peer->tree);

	data_buffer_len = peer->chunk_size + 4 + 1 + 4 + 4 + 8;
	data_buffer = malloc(data_buffer_len);
	
	/* concatenate phrase "download_" and downloading file to avoid overwriting original file */
	sprintf(fname, "%s_%s", FILE_DOWNLOAD, peer->fname);
	
	unlink(fname);
	
	fd = open(fname, O_WRONLY | O_CREAT, 0744);
	if (fd < 0) {
		printf("error opening file '%s' for writing: %u %s\n", fname, errno, strerror(errno));
		abort();
	}

	z = peer->start_chunk;
	while (z < peer->end_chunk) {
		printf("-----------z: %u  peer->end_chunk: %u\n", z, peer->end_chunk);
		begin = z;

		if (z + hashes_per_mtu >= peer->end_chunk)
			end = peer->end_chunk;
		else
			end = z + hashes_per_mtu -1 ;

		printf("begin: %lu   end: %lu\n", begin, end);
		
		/* create REQUEST  */
#warning FIXME poprawic ten peer->request na jakis bufor lokalny
		peer->request_len = make_request(peer->request, 0xfeedbabe, begin, end);
		if (peer->request_len > 256) {
			printf("peer->request_len > 256: %u\n", peer->request_len);
			abort();
		}
		
		/* send REQUEST */
		n = sendto(sockfd, peer->request, peer->request_len, 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
		if (n < 0) {
			printf("error sending request: %d\n", n);
			//return -1;
			abort();
		}
		printf("request message 3/3 sent\n");
		
		/* receive INTEGRITY from SEEDER */
		n = recvfrom(sockfd, (char *)buffer, BUFSIZE, 0, (struct sockaddr *) &servaddr, &len);
		if (n < 0) {
			printf("error: recvfrom: %d errno: %d %s\n", n, errno, strerror(errno));
			printf("	len: %d\n", len);
			//return -1;
			abort();
		}
		printf("server sent INTEGRITY: %d\n", n);
		dump_integrity(buffer, n, peer);		/* copy SHA hashes to peer->chunk[] */


		/* copy all the received now SHA hashes to tree */
		printf("kopiowanie sha %lu-%lu =================================\n", begin, end);
		for (x = begin; x < end; x++)
			memcpy(peer->tree[2 * x].sha, peer->chunk[x].sha, 20);

		/* receive the whole range of chunks from SEEDER */
		for (cc = begin; cc <= end; cc++) {
			peer->curr_chunk = cc;
			
			/* receive single DATA datagram */
			nr = recvfrom(sockfd, (char *)data_buffer, data_buffer_len, 0, (struct sockaddr *) &servaddr, &len);
			if (nr <= 0) {
				printf("error: recvfrom: %d errno: %d %s\n", n, errno, strerror(errno));
				//return -1;
				abort();
			}

			/* save received chunk to disk */
			lseek(fd, cc * peer->chunk_size, SEEK_SET);
			write(fd, data_buffer + 1 + 4 + 4 + 8 + 4, nr - (1 + 4 + 4 + 8 + 4));

			/* calculate SHA hash */
			SHA1Reset(&context);
			SHA1Input(&context, data_buffer + 1 + 4 + 4 + 8 + 4 , nr - (1 + 4 + 4 + 8 + 4)); /* skip the headers */
			SHA1Result(&context, digest);

			/* convert to ASCII calculated locally SHA hash */
			s = 0;
			for (y = 0; y < 20; y++)
				s += sprintf((char *)(sha_buf + s), "%02x", digest[y] & 0xff);
			sha_buf[40] = '\0';

			/* convert to ASCII remote SHA hash from SEEDER */
			s = 0;
			for (y = 0; y < 20; y++)
				s += sprintf((char *)(sha_seeder_buf + s), "%02x", peer->chunk[peer->curr_chunk].sha[y] & 0xff);
			sha_seeder_buf[40] = '\0';
			
			/* compare both SHA hashes: calculated locally and remote from SEEDER */
			cmp = memcmp(peer->chunk[peer->curr_chunk].sha, digest , 20);
			
			if (cmp != 0) {
				printf("error - hashes are different[%lu]: seeder %s vs digest: %s\n", cc, sha_seeder_buf, sha_buf);
				abort();
			}
			
			/* create ACK message to confirm that chunk in last DATA datagram has been transferred correctly */
			ack_len = make_ack(buffer, peer);
			if (ack_len > BUFSIZE) {
				printf("ack_len > BUFSIZE: %lu\n" , ack_len);
				abort();
			}
			
			/* send ACK */
			n = sendto(sockfd, buffer, ack_len, 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
			if (n < 0) {
				printf("error sending request: %d\n", n);
				//return -1;
				abort();
			}
			printf("ACK[%lu] sent\n" ,cc);
		}
		
		z += hashes_per_mtu;
	}
	
	/* send HANDSHAKE FINISH */
	n = make_handshake_finish(buffer, peer);
	n = sendto(sockfd, buffer, ack_len, 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
	if (n < 0) {
		printf("error sending request: %d\n", n);
		//return -1;
		abort();
	}
	printf("HANDSHAKE_FINISH sent\n");
	
	
	free(data_buffer);
	close(sockfd);
	close(fd);
	return 0;
	
}

