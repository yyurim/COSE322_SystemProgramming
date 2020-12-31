#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/timeb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>

#include <pthread.h>

#define MAX_PORT 9		    // maximum number of ports
#define MAX_CONNECTION 5	// maximum number of connections per ports
#define MAX_MSG 65536		// maximum size of message


// initialize ports
// 	returns the number of available ports
int init_ports(int *ports) {

	// input : the number of ports client use
	int port_num;
	scanf("%d",&port_num);

	// input : user defines the port numbers
	for(int i = 0; i < port_num; i++){
		int p;
		scanf("%d",&p);
		ports[i] = p;
	}

	return port_num;
}


// create socket
//	args : 	idx_port_mapping -> to check connection number per ports
//		client_socket -> socket fd
//		port -> socket location,
//		socket_connection_num -> connection number per ports
void create_socket(int* idx_port_mapping, int *client_socket, int port, int* socket_connection_num) {
	int loc = -1;					    // index of port in idx_port_mapping
	int last_idx = MAX_PORT-1;			// last valid information in idx_port_mapping

	// table lookup for idx-port mapping to manage connection number per ports
	for(int i = 0 ; i < MAX_PORT ; i++){
		if(idx_port_mapping[i]==port){
			loc = i;
			break;
		}
		if(idx_port_mapping[i]==0){
			last_idx = i;
			break;
		}
	}

	// check if there is available connection, which means ports keeps less than 5 connections.
	if(loc==-1){
		// if the port number never appeared before,
		//	update mapping information and increase connection number.
		idx_port_mapping[last_idx] = port;
		socket_connection_num[last_idx] +=1;
	}
	else{
		if(socket_connection_num[loc] >= MAX_CONNECTION){
			printf("\nClient : Port %d has no available connection\n", port);
			exit(0);
		}
		// increase connection number of the port
		socket_connection_num[loc] +=1;
	}

	// create an endpoint for communication
	//	args : PF_INET -> IPv4, SOCK_STREAM -> TCP 
	*client_socket = socket(PF_INET, SOCK_STREAM, 0);
	
	// error handling
	// 	if impossible to create an socket on selected port
	if (*client_socket == -1)
	{
		printf("\nClient : Can't open stream socket, port %d \n", port);
		exit(0);
	}

	return;
}

// set server information
void configure_server(struct sockaddr_in *server_addr, char *server_IP, int port) {

	memset(server_addr, 0, sizeof(*server_addr));

	server_addr->sin_family = AF_INET;                  	// IPv4
	server_addr->sin_port = htons(port);          		    // port
	server_addr->sin_addr.s_addr = inet_addr(server_IP); 	// server IP address

	return;
}

// connect socket to server
void connect_server(struct sockaddr_in *server_addr, int client_socket, int port) {

	if (connect(client_socket, (struct sockaddr *)server_addr, sizeof(*server_addr)) < 0){
		printf("\nConnection failed, port %d\n", port);
		exit(0);
	}

	return;
}

// for log
char *get_current_time() {

    struct timeb itb;
    struct tm *lt;
    static char s[20];

    ftime(&itb);

    lt = localtime(&itb.time);

    sprintf(s, "%02d:%02d:%02d.%03d", lt->tm_hour, lt->tm_min, lt->tm_sec, itb.millitm);

    return s;
}

// a trigger function for finishing connection between server and client
//	if '@' appears more than 5 times, connection terminated.
int atsign_counting(const char * const buf, size_t len){
	int i;
	int n = 0;
	for (i = 0; i < len; i++) {
		if (buf[i] == '@')
			n++;
	}
	return n;
} 

// a struct for implementing function, pthread_create() : args in args
typedef struct _pthread_args {
	int *client_socket;
	int port;
}p_thread_args;

// Clients receive server's msg
void *server_msg(void *pThreadArgs) {

	int msg_len;         		// message size
	char msg_buffer[MAX_MSG]; 	// message buffer

	int client_socket_fd = *(((p_thread_args *)pThreadArgs)->client_socket);
	int port_num = ((p_thread_args *)pThreadArgs)->port;

	// initialize log file
	FILE *fp;
	char log_path[20];

	// set log path
	sprintf(log_path, "./log/%d_%d.txt", port_num,client_socket_fd);

	// open log file
	fp = fopen(log_path, "w");

	if (!fp){
		printf("Client : File open failed\n");
		exit(0);
	}

	while(1){
		int atsign_count = 0;	// trigger variable for terminating connection
		char log_temp[80];	// buffer for writing msg to log, different from msg buffer

		memset(log_temp,0,sizeof(log_temp));
		memset(msg_buffer,0,sizeof(msg_buffer));

		// read msg
		//	receive msg through client_socket_fd,
		//	store it in msg_buffer,
		//	and return the length of received msg
		msg_len = recv(client_socket_fd, msg_buffer, MAX_MSG, 0);

		// write log
		//	write current time, msg size, msg to log file
		sprintf(log_temp, "%s | %d | %s", get_current_time(), msg_len, msg_buffer);
		fputs(log_temp, fp);
		fputs("\n", fp);

		// check if connection finished
		atsign_count += atsign_counting(msg_buffer, msg_len);
		if (atsign_count >= 5){
			fclose(fp);
			return;
		}
	}

	fclose(fp);

	return;
}

// create threads
void create_thread(pthread_t *p_thread, int *client_socket, int port, int log_num) {

	int thread_ID;

	// set pthread_create args
	p_thread_args *pThreadArgs = (p_thread_args *)malloc(sizeof(p_thread_args));
	pThreadArgs->client_socket = client_socket;
	pThreadArgs->port = port;

	// create pthread : dealing with server_msg
	thread_ID = pthread_create(p_thread, NULL, server_msg, (void *)pThreadArgs);

	// error
	if (thread_ID < 0){
		perror("Client : Can't create thread.");
		exit(0);
	}


	return;
}

// Terminate connection
void close_sockets(int *client_socket, int port_num) {
	printf("Close\n");

	for (int i = 0; i < port_num; i++){
		close(client_socket[i]);
	}

	return;
}


int main(int argc, char *argv[]) {

	int client_socket[MAX_PORT];                 	// client socket
	int ports[MAX_PORT];                  		    // port number for each sockets
	char server_IP[20];                           	// server ip address
	struct sockaddr_in client_addr[MAX_PORT]; 	    // address for each client
	struct sockaddr_in server_addr;            	    // server address

	pthread_t p_thread[MAX_PORT]; 			        // thread
	int status[MAX_PORT];                           // thread status

	int i; 						                    // index for managing ports
	int port_num;					                // the number of ports

	printf("Enter server IPv4 address: ");
	scanf("%s", server_IP);

	// repeat until ctrl-c
	while(1){
		int idx_port_mapping[MAX_PORT] = {0,};		// to keep max connection
		int socket_connection_num[MAX_PORT] = {0,};	// the number of connection per socket

		// intialize ports
		port_num = init_ports(ports);

		printf("Open : ");
		// connect each sockets to the server
		for (i = 0; i < port_num; i++){

			// create a socket at port[i]
			create_socket(idx_port_mapping, &client_socket[i], ports[i], socket_connection_num);

			// if created, print port number
			printf("%6d  ",ports[i]);

			// initialize server information for connection
			configure_server(&server_addr, server_IP, ports[i]);

			// connect the socket to the server
			connect_server(&server_addr, client_socket[i], ports[i]);

		}
		printf("\n");

		// create threads
		for (i = 0; i < port_num; i++){
			create_thread(&p_thread[i], &client_socket[i], ports[i], i);
		}

		// wait threads
		for (i = 0; i < port_num; i++){
			pthread_join(p_thread[i], (void *)&status[i]);
		}

		// close sockets
		close_sockets(client_socket, port_num);
	}

    return 0;
}


