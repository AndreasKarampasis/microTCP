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
 * You can use this file to write a test microTCP client.
 * This file is already inserted at the build system.
 */

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "../lib/microtcp.h"

#define DESTPORT 3500
int main(int argc, char **argv) {
	// uint8_t* buffer;
	microtcp_sock_t socket;
	socklen_t client_addr_len;
	struct sockaddr* client_addr;
	int recieved;
	char* buffer = "zoro kai buzz";
/*	char* buffer = 0;
	long length;
	FILE * f = fopen("infile.txt", "r");
	if (f) {
		fseek (f, 0, SEEK_END);
		length = ftell(f);
		fseek (f, 0, SEEK_SET);
		buffer = malloc(length);
		if (buffer) {
			fread(buffer, 1, length, f);
		}
		fclose (f);
	}
*/
	socket = microtcp_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (socket.state == INVALID){
		fprintf(stderr, "Opening microTCP socket\n");
		// free(buffer);
		exit(EXIT_FAILURE);
	}

	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(struct sockaddr_in));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(3500);
	sin.sin_addr.s_addr = inet_addr("127.0.0.1");
	printf("\nmicroTCP Client: starting 3way handshake!\n");
	recieved = microtcp_connect(&socket,(struct sockaddr *) &sin, sizeof(struct sockaddr_in));
	if (recieved == -1) {
        perror("ERROR");
        return 1;
    }
	printf("\nmicroTCP Client: 3way handshake success!\n");
	puts("microTCP Client: Sending hello message.");
	// microtcp_send(&socket, buffer, length, 0);
	microtcp_send(&socket, buffer, strlen(buffer), 0);

	printf("\nmicroTCP Client: Starting microTCP shutdown\n");
	microtcp_shutdown(&socket, 0);
	printf("\nmicroTCP Client: Shutdown success!\n");

  return 0;
}
