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

#include "microtcp.h"
#include "../utils/crc32.h"

microtcp_sock_t
microtcp_socket (int domain, int type, int protocol) {
  microtcp_sock_t sock;
  struct timeval timeout;
  if ((sock.sd = socket(domain, type, protocol)) == -1) {
    perror("Create microTCP socket failed ");
    sock.state = INVALID;
    return sock;
  }
  sock.address = (struct sockaddr*)malloc(sizeof(struct sockaddr));
  sock.state = UNKNOWN;
  timeout.tv_sec = 0;
  timeout.tv_usec = MICROTCP_ACK_TIMEOUT_US;
  if (setsockopt(sock.sd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval)) < 0) {
    perror("setsockop");
  }
  return sock;
}

int
microtcp_bind (microtcp_sock_t *socket, const struct sockaddr *address,
               socklen_t address_len) {
  int ret_val = bind(socket->sd, address, address_len); 
  if (ret_val == -1) {
    perror("MicroTCP bind");  
  }
  return ret_val;
}

int
microtcp_connect (microtcp_sock_t *socket, const struct sockaddr *address,
                  socklen_t address_len) {
  microtcp_header_t header_to_send, header_to_recv;
  ssize_t bytes_received, bytes_sent;
  int ret_val;

  srand(time(NULL)); 
  // socket->seq_number = rand();
  socket->seq_number = 0;
  printf("Client: seq number %d\n", socket->seq_number);

  //************* Send first packet of 3-way handshake **************************
  header_to_send.seq_number   = htonl(socket->seq_number);
  header_to_send.ack_number   = 0;
  header_to_send.control      = htons(SYN);
  header_to_send.window       = 0;
  header_to_send.data_len     = 0;
  header_to_send.future_use0  = 0;
  header_to_send.future_use1  = 0;
  header_to_send.future_use2  = 0;
  header_to_send.checksum     = 0; 

  puts("Client: Sending 1st packet of handshake");
  bytes_sent = sendto(socket->sd, &header_to_send, sizeof(microtcp_header_t), 0,
                    address, address_len);
  if (bytes_sent == -1) {
    perror("MicroTCP failed to send SYN segment.");  
    socket->state = INVALID;
    return -1;
  }
  socket->packets_send++;
  socket->bytes_send += bytes_sent;
  //*************** Receive Second packet of 3-way handshake **********************
  puts("Client: Waiting 2nd packet of handshake from server");

  bytes_received = recvfrom(socket->sd, &header_to_recv, sizeof(microtcp_header_t), 0,
                      (struct sockaddr* )address, &address_len);
  // Error checking ...
  if (bytes_received == -1) {
    perror("MicroTCP failed to receive SYN-ACK segment.");  
    socket->state = INVALID;
    return -1;
  }
  if (ntohs(header_to_recv.control) != (SYN | ACK)) {
    perror("MicroTCP connect refused connection. Control is not SYN-ACK.");
    socket->state = INVALID;
    return -1;  
  }
  printf("Server: seq number %d\n", ntohl(header_to_recv.seq_number));
  printf("Server: ack number %d\n", ntohl(header_to_recv.ack_number));

  // Update socket's info
  socket->seq_number    = ntohl(header_to_recv.ack_number);
  socket->ack_number    = ntohl(header_to_recv.seq_number) + 1;
  socket->recvbuf       = (uint8_t *)malloc(MICROTCP_RECVBUF_LEN);
  socket->buf_fill_level= 0;
  socket->init_win_size = ntohs(header_to_recv.window);
  socket->curr_win_size = socket->init_win_size;

  puts("Client: Received 2nd packet of handshake from server");
  puts("Client: Sending 3rd packet of handshake");
  //************* Send third packet of 3-way handshake **************************
  header_to_send.seq_number   = htonl(socket->seq_number);
  header_to_send.ack_number   = htonl(socket->ack_number);
  header_to_send.control      = htons(ACK);
  header_to_send.window       = htons(socket->init_win_size);
  header_to_send.data_len     = 0;
  header_to_send.future_use0  = 0;
  header_to_send.future_use1  = 0;
  header_to_send.future_use2  = 0;
  header_to_send.checksum     = 0; 
  
  ret_val = sendto(socket->sd, &header_to_send, sizeof(microtcp_header_t), 0,
                    address, address_len);
  // Error checking ...
  if (ret_val == -1) {
    perror("MicroTCP failed to send ACK segment.");  
    socket->state = INVALID;
    return -1;
  }
  printf("Client: seq number %d\n", socket->seq_number);
  printf("Client: ack number %d\n", socket->ack_number);
  printf("Client: cur win size %ld\n", socket->curr_win_size);
  printf("Client: cur init size %ld\n", socket->init_win_size);
 
  memcpy(socket->address, address, sizeof(struct sockaddr));
  memcpy(&socket->address_len, &address_len, sizeof(socklen_t));
  // Now TCP connection is established
  socket->state = ESTABLISHED;
  return 0;
}

int
microtcp_accept (microtcp_sock_t *socket, struct sockaddr *address,
                 socklen_t address_len) {
  microtcp_header_t header_to_send, header_to_recv;
  ssize_t bytes_received, bytes_sent;

  puts("Server: Waiting 1st packet of handshake from client");
  // Receive SYN from client
  do {
  bytes_received = recvfrom(socket->sd, &header_to_recv, sizeof(microtcp_header_t), 0,
                      address, &address_len);
  } while (bytes_received < 0);
  puts("Server: Received 1st packet of handshake from client");
  // Error checking ...
  if (bytes_received == -1) {
    perror("MicroTCP connection failed 1st packet of handshake. ");  
    socket->state = INVALID;
    return -1;
  } 
  if (ntohs(header_to_recv.control) != SYN) {
    perror("MicroTCP refused connection. Segment is not SYN.");  
    socket->state = INVALID;
    return -1;
  }
  // Update socket's info
  // socket->seq_number = rand();
  socket->seq_number    = 0;
  socket->ack_number    = ntohl(header_to_recv.seq_number) + 1;
  socket->init_win_size = MICROTCP_INIT_CWND;
  socket->curr_win_size = socket->init_win_size;
  socket->recvbuf       = (uint8_t *)malloc(MICROTCP_RECVBUF_LEN);
  socket->buf_fill_level= 0;
  socket->ssthresh = MICROTCP_INIT_SSTHRESH;
  if (socket->recvbuf == NULL) {
    printf("ERROR: Not enough memory.\n");
    socket->state = INVALID;
    return -1;
  }

  printf("Server: seq number %d\n", socket->seq_number);
  printf("Server: ack number %d\n", socket->ack_number);
  // Send SYN-ACK to client
  header_to_send.seq_number   = htonl(socket->seq_number);
  header_to_send.ack_number   = htonl(socket->ack_number);
  header_to_send.control      = htons(SYN | ACK);
  header_to_send.window       = htons(socket->init_win_size);
  header_to_send.data_len     = 0;
  header_to_send.future_use0  = 0;
  header_to_send.future_use1  = 0;
  header_to_send.future_use2  = 0;
  header_to_send.checksum     = 0;

  puts("Server: Sending 2nd packet of handshake to client");
  bytes_sent = sendto(socket->sd, &header_to_send, sizeof(microtcp_header_t), 0,
                      address, address_len);
  if (bytes_sent == -1) {
    perror("MicroTCP failed to send ACK segment.");  
    socket->state = INVALID;
    return -1;
  }
  
  bytes_received = recvfrom(socket->sd, (void *)&header_to_recv, sizeof(microtcp_header_t), 0,
                            address, &address_len);
  // Error checking ...
  if (bytes_received == -1) {
    perror("MicroTCP connection failed. ");  
    socket->state = INVALID;
    return -1;
  } 
  if (ntohs(header_to_recv.control) != ACK) {
    perror("MicroTCP refused connection. Segment is not SYN.");  
    socket->state = INVALID;
    return -1;
  }
  printf("Server: cur win size %ld\n", socket->curr_win_size);
  printf("Server: cur init size %ld\n", socket->init_win_size);
  memcpy(socket->address, address, sizeof(struct sockaddr));
  memcpy(&socket->address_len, &address_len, sizeof(socklen_t));
  socket->seq_number = ntohl(header_to_recv.ack_number);
  socket->state = ESTABLISHED;
  return 0;
}

int
microtcp_shutdown (microtcp_sock_t *socket, int how) {
  microtcp_header_t header_to_recv, header_to_send;
  ssize_t bytes_sent, bytes_received;
  switch (socket->state) {
    case CLOSING_BY_PEER:
      header_to_send.seq_number   = htonl(socket->seq_number);
			header_to_send.ack_number   = htonl(socket->ack_number);
			header_to_send.control      = htons(FIN);
			header_to_send.window       = htons(socket->curr_win_size);
			header_to_send.data_len     = 0;
			header_to_send.future_use0  = 0;
			header_to_send.future_use1  = 0;
			header_to_send.future_use2  = 0;
			header_to_send.checksum     = 0;

      bytes_sent = sendto(socket->sd, &header_to_send, sizeof(microtcp_header_t), 0,
                      socket -> address, socket -> address_len);

      if (bytes_sent == -1) {
        perror("MicroTCP shutdown failed to send FIN segment.");  
        return -1;
      }
      puts("Server: Sending FIN");
      printf("Server: seq number %d\n", socket->seq_number);
      printf("Server: ack number %d\n", socket->ack_number);

      bytes_received = recvfrom(socket->sd, (void *)&header_to_recv, sizeof(microtcp_header_t), 
                                  0, socket->address, &(socket->address_len));
			// Error...
			if (bytes_received == -1) {
				perror("MicroTCP shutdown. Failed to receive data from client.");
				return -1;
			}
 
			if (ntohs(header_to_recv.control) != ACK) {
				perror("Shutdown error. segment from client is not FIN ");
				return -1;
			}
      break;
    default:
      // SEND FIN
      header_to_send.seq_number   = htonl(socket->seq_number);
      header_to_send.ack_number   = htonl(socket->ack_number);
      header_to_send.control      = htons(FIN);
      header_to_send.window       = htons(socket->curr_win_size);
      header_to_send.data_len     = 0;
      header_to_send.future_use0  = 0;
      header_to_send.future_use1  = 0;
      header_to_send.future_use2  = 0;
      header_to_send.checksum     = 0;

      bytes_sent = sendto(socket->sd, &header_to_send, sizeof(microtcp_header_t), 0,
                          socket->address, socket->address_len);
      if (bytes_sent == -1) {
        perror("MicroTCP shutdown failed to send FIN segment.");  
        return -1;
      }
      puts("Client: Sending FIN");
      printf("Client: seq number %d\n", socket->seq_number);
      printf("Client: ack number %d\n", socket->ack_number);
      bytes_received = recvfrom(socket->sd, &header_to_recv, sizeof(microtcp_header_t), 0,
                      socket->address, &socket->address_len);
      // Error checking ...
      if (bytes_received == -1) {
        perror("MicroTCP shutdown. Failed to receive data from server.");
        return -1;
      }
      if (ntohs(header_to_recv.control) != ACK) {
        perror("MicroTCP shutdown. Segment from server is not ACK.");
        return -1;
      }
      socket->state = CLOSING_BY_HOST;

      bytes_received = recvfrom(socket->sd, &header_to_recv, sizeof(microtcp_header_t), 0,
                      socket->address, &socket->address_len);
      // Error checking ...
      if (bytes_received == -1) {
        perror("MicroTCP timeout");
        return -1;
      }
      if (ntohs(header_to_recv.control) != FIN) {
        perror("MicroTCP shutdown. Segment from server is not FIN.");
        return -1;
      }
      // Update socket's info
      socket->seq_number = ntohl(header_to_recv.ack_number);
      // socket->ack_number = ntohl(header_to_recv.seq_number) + bytes_received;
      socket->ack_number = ntohl(header_to_recv.seq_number) + 1;
      
      header_to_send.seq_number   = htonl(socket->seq_number);
      header_to_send.ack_number   = htonl(socket->ack_number);
      header_to_send.control      = htons(ACK);
      header_to_send.window       = htons(socket->curr_win_size);
      header_to_send.data_len     = 0;
      header_to_send.future_use0  = 0;
      header_to_send.future_use1  = 0;
      header_to_send.future_use2  = 0;
      header_to_send.checksum     = 0;
      bytes_sent = sendto(socket->sd, &header_to_send, sizeof(microtcp_header_t), 0,
                          socket->address, socket->address_len);
      if (bytes_sent == -1) {
        perror("MicroTCP timeout");
        return -1;
      }
      puts("Client: Sending ACK");
      printf("Client: seq number %d\n", socket->seq_number);
      printf("Client: ack number %d\n", socket->ack_number);
      break;
  }
  free(socket->recvbuf);
  socket->state = CLOSED;
  return 0;
}

ssize_t
microtcp_send (microtcp_sock_t *socket, const void *buffer, size_t length,
               int flags) {
  microtcp_header_t header_to_send, *header_to_recv;  
  ssize_t bytes_send, bytes_recv;
  size_t i, chunks = 0, remaining = length, bytes_to_send;
  // sizeof header + sizeof data
  void* packet = malloc(sizeof(microtcp_header_t) + MICROTCP_MSS);
  if (!packet) return -1;
  header_to_recv = malloc(sizeof(microtcp_header_t));
  if (!header_to_recv) return -1;
  if (socket->state != ESTABLISHED) {
    free(packet);
    free(header_to_recv);
    return -1;
  } 
  while (remaining > 0) {
    bytes_to_send = min((size_t)MICROTCP_WIN_SIZE, min(socket->curr_win_size, remaining));
    chunks = length / MICROTCP_MSS;
    printf("Packet split in %ld chunks.\n", chunks);

    for (i = 0; i < chunks; ++i) {
      // Theloyme to cast giati einai void*
      ((microtcp_header_t *)packet)->seq_number  = htonl(socket->seq_number + (i * sizeof(packet)));
      ((microtcp_header_t *)packet)->ack_number  = htonl(socket->ack_number);
      ((microtcp_header_t *)packet)->control     = 0;
      ((microtcp_header_t *)packet)->window      = 0;
      ((microtcp_header_t *)packet)->data_len    = 0;
      ((microtcp_header_t *)packet)->future_use0 = 0;
      ((microtcp_header_t *)packet)->future_use1 = 0;
      ((microtcp_header_t *)packet)->future_use2 = 0;
      ((microtcp_header_t *)packet)->checksum    = 0;
      // Copy data 
      memcpy(packet + sizeof(microtcp_header_t), buffer + (i*MICROTCP_MSS), MICROTCP_MSS);
      // CRC32 
      ((microtcp_header_t *)packet)->checksum    = htonl(crc32(packet, sizeof(packet)));
      // Send data
      bytes_send = sendto(socket->sd, packet, sizeof(microtcp_header_t) + MICROTCP_MSS, 
          flags, socket->address, socket->address_len);
      printf("Client sent %ld bytes\n%ld bytes remaining.\n", bytes_send, remaining - bytes_send);
        
      // Update socket info
      socket->bytes_send = socket->bytes_send + bytes_send; 
      socket->packets_send++;
    }
    // Check if there is a semi-filled chunk 
    if (bytes_to_send % MICROTCP_MSS) {
      ((microtcp_header_t *)packet)->seq_number  = htonl(socket->seq_number + (chunks * (bytes_to_send % MICROTCP_MSS)));
      ((microtcp_header_t *)packet)->ack_number  = htonl(socket->ack_number);
      ((microtcp_header_t *)packet)->control     = 0;
      ((microtcp_header_t *)packet)->window      = 0;
      ((microtcp_header_t *)packet)->data_len    = 0;
      ((microtcp_header_t *)packet)->future_use0 = 0;
      ((microtcp_header_t *)packet)->future_use1 = 0;
      ((microtcp_header_t *)packet)->future_use2 = 0;
      ((microtcp_header_t *)packet)->checksum    = 0;
      // Copy data 
      memcpy(packet + sizeof(microtcp_header_t), buffer + (chunks * (bytes_to_send % MICROTCP_MSS)), MICROTCP_MSS);
      // CRC32 
      ((microtcp_header_t *)packet)->checksum    = htonl(crc32(packet, sizeof(packet)));
      ++chunks;
      printf("Semi-filled chunk. new chunks: %ld.\n", chunks);
      // Send data
      bytes_send = sendto(socket->sd, packet, sizeof(microtcp_header_t) + (length % MICROTCP_MSS), 
          flags, socket->address, socket->address_len);
      // Update socket info
      socket->bytes_send = socket->bytes_send + bytes_send; 
      socket->packets_send++;
      printf("Client sent %ld bytes\n%ld bytes remaining.\n", bytes_send, remaining - bytes_send);

    }

    // cur_win == 0 flow control
    if (socket->curr_win_size == 0) {
     ((microtcp_header_t *)packet)->seq_number  = htonl(socket->seq_number);
     sleep(rand() % MICROTCP_ACK_TIMEOUT_US);
     // Send message with no data
     bytes_send = sendto(socket->sd, packet, sizeof(microtcp_header_t), 
         flags, socket->address, socket->address_len);
     ++chunks;
    }
    for (i = 0; i < chunks; ++i) {
     printf("Client waiting ACK %ld.\n", i);
     bytes_recv = recvfrom(socket->sd, header_to_recv, sizeof(microtcp_header_t), 0, 
                           socket->address, &(socket->address_len));
     if (bytes_recv == -1) {
      perror("MicroTCP send timeout");
      break;
     }
     if (ntohs(header_to_recv->control) != ACK) break;
     socket->bytes_received = socket->bytes_received + bytes_recv;
     socket->packets_received++;
     if (ntohl(header_to_recv->ack_number) != socket->seq_number + bytes_send) {
       break;
     } 
    } 
    // Retransmission 
    // Update window 
    // Update congestion control 
    remaining -= bytes_to_send;
  }
 // socket->seq_number = ntohl(header_to_recv->ack_number);
 // socket->ack_number = ntohl(header_to_recv->seq_number);
  printf("Client: seq number %d\n", socket->seq_number);
  printf("Client: ack number %d\n", socket->ack_number);
  return bytes_send;
}

ssize_t
microtcp_recv (microtcp_sock_t *socket, void *buffer, size_t length, int flags) {
  microtcp_header_t  header_to_send;
  ssize_t bytes_received, bytes_send;
  uint32_t checksum;
  size_t remaining = length;
  int i, j = 1;
  uint8_t* packet = malloc(sizeof(microtcp_header_t) + length);
  if (!packet) return -1;

  // Receive from socket and store in buf
  bytes_received = recvfrom(socket->sd, packet, sizeof(microtcp_header_t) + length, flags,
                              socket->address, &(socket->address_len));
  // Error checking
  if (bytes_received == -1) {
    perror("MicroTCP timeout");
    return -1;
  }
  // crc32
  checksum = htonl(((microtcp_header_t*)packet)->checksum);
  ((microtcp_header_t*)packet)->checksum = 0;
  printf("Server received %ld bytes.\n", bytes_received);
  printf("\nChecksum recvd: %d checksum calc: %d\n", checksum, crc32(packet, sizeof(packet)));
  if (checksum != 0 && checksum != crc32(packet, sizeof(packet))) {
    puts("Checksum error");
    socket->bytes_lost = socket->bytes_lost + bytes_received;
    socket->packets_lost++;
  } else {
    puts("No checksum error.");
      // Update socket info
    socket->packets_received++;
    socket->bytes_received += bytes_received;
    socket->ack_number = socket->ack_number + bytes_received;
  }

  header_to_send.seq_number  = htonl(socket->seq_number);
  header_to_send.ack_number  = htonl(socket->ack_number);
  header_to_send.control     = htons(ACK);
  header_to_send.window      = htons(socket->init_win_size);
  header_to_send.data_len    = 0;
  header_to_send.future_use0 = 0;
  header_to_send.future_use1 = 0;
  header_to_send.future_use2 = 0;
  header_to_send.checksum    = 0;
  /* Send ACK */
  bytes_send = sendto(socket->sd, &header_to_send, sizeof(microtcp_header_t), flags,
  socket->address, socket->address_len);
  socket->bytes_send = socket->bytes_send + bytes_send; 
  socket->packets_send++;
  /* Client requesting shutdown */
  if (ntohs(((microtcp_header_t*)packet)->control) == FIN) {
    socket->state = CLOSING_BY_PEER;
	  printf("\nmicroTCP Server: Starting microTCP shutdown\n");
    microtcp_shutdown(socket, 0);
    return -1;
  }
  printf("Server: seq number %d\n", socket->seq_number);
  printf("Server: ack number %d\n", socket->ack_number);
  /* Copy data only to recv buffer */
  memcpy(socket->recvbuf + socket->buf_fill_level, packet+sizeof(microtcp_header_t) , bytes_received- sizeof(microtcp_header_t)); 
  /* copy data */
  memcpy(buffer, packet + sizeof(microtcp_header_t), length);
  return bytes_received;
}
