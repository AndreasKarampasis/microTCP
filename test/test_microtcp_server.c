/*
 * microtcp, a lightweight implementation of TCP for teaching,
 * and academic purposes.
 *
 * Copyright (C) 2015-2017  Manolis Surligas <surligas@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * You can use this file to write a test microTCP server.
 * This file is already inserted at the build system.
 */
#include <arpa/inet.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include "../lib/microtcp.h"

#define MYPORT 3500
#define MAXLINE 1024
int main(int argc, char **argv) {
	microtcp_sock_t socket;
	uint8_t buffer[3000] = {0};
	int accepted;
	int received;

	ssize_t written;
	ssize_t total_bytes = 0;
	socklen_t client_addr_len;
	// FILE * f = fopen ("outfile.txt", "w");

	struct sockaddr_in sin;
	struct sockaddr client_addr;
	struct timespec start_time;
	struct timespec end_time;

	if(!buffer){
		perror("Allocate application receive buffer");
		exit(EXIT_FAILURE);
	}

	socket = microtcp_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (socket.state == INVALID){
		perror("Opening microTCP socket");
		exit(EXIT_FAILURE);
	}

	memset(&sin, 0, sizeof(struct sockaddr_in));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(3500);
	/* Bind to all available network interfaces */
	sin.sin_addr.s_addr = INADDR_ANY;

  microtcp_bind(&socket, (struct sockaddr *) &sin, sizeof(struct sockaddr_in));

	/* Accept a connection from the client */
	client_addr_len = sizeof(struct sockaddr);

	received = microtcp_accept(&socket, &client_addr, client_addr_len);
	if (received == -1) {
        perror("ERROR");
        return 1;
    }
	printf("\nmicroTCP Server - 3way handshake Success!\n");
	printf("\nmicroTCP Server - Receiving data.\n");
	while ((received = microtcp_recv(&socket, buffer, sizeof(buffer), 0)) > 0) {
		printf("microTCP: Server received %s of %d bytes.\n", buffer, received);
		// fwrite(buffer , 1, received , buffer);
	}

	// printf("\nmicroTCP Server: Starting microTCP shutdown\n");
    // microtcp_shutdown(&socket, 0);
	printf("\nmicroTCP Server: Shutdown success!\n");

    return 0;
}
