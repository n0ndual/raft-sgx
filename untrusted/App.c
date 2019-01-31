/* App.c
*
* Copyright (C) 2006-2016 wolfSSL Inc.
*
* This file is part of wolfSSL.
*
* wolfSSL is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* wolfSSL is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
*/


#include "stdafx.h"
#include "App.h" /* contains include of Enclave_u.h which has wolfSSL header files */
#include "logging.h"

/* Use Debug SGX ? */
#if _DEBUG
	#define DEBUG_VALUE SGX_DEBUG_FLAG
#else
	#define DEBUG_VALUE 1
#endif

/* the usual suspects */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

/* socket includes */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#include <sgx_uae_service.h>
#include <sgx_ukey_exchange.h>

#include <libdill.h>

#include <wolfssl/certs_test.h>


typedef struct raft_peer_s{
  char ip[46];
  int port;
  int tcp_connected;
  int socket;
  int is_client;
  struct raft_peer_s* next;
} raft_peer_t;

raft_peer_t* raft_peers;

coroutine void raft_conn_new(sgx_enclave_id_t eid, WOLFSSL_CTX* ctx, raft_peer_t* peer ) {
  int sgx_status;
  void* raft_conn;
  sgx_status = ecall_raft_peer_new(eid, &raft_conn, ctx,
                                   peer->ip, strlen(peer->ip)+1, peer->socket, peer->is_client);

  unsigned char* buf_recv = malloc(sizeof(unsigned char));
  unsigned char* buf_send = malloc(2048*sizeof(unsigned char));
  memset(buf_send, '\0', 2048);
  int len_to_flush = 0;
  int s = peer->socket;

  while(1){

    //try flush buffers: 1, tls tcp_send buffer; 2, flush tls_send buffers;
    Debug("try flush tls and tcp\n");
    sgx_status = ecall_pull_tcp_send(eid, &len_to_flush, raft_conn, buf_send, 2048);
    if(sgx_status !=0){
      Debug("ecall_pull_tcp_send failed\n");
      break;
    }else if(len_to_flush > 0){
      Debug("len to send:%d\n", len_to_flush);
      int rc = bsend(s, buf_send, len_to_flush, -1);
      if(rc<0){
        Debug("bsend %d bytes ret: %d %d\n", len_to_flush, rc, errno);
        break;
      }else{
        Debug("send %d butes succeeded\n", len_to_flush);
      }
    }

    // recv tcp data, and feed to the associated enclave.
    int ret =  brecv(s, buf_recv, 1, -1);
    if(ret < 0){
      Debug("brecv error: %d\n",errno);
      break;
    }
    printf("try flush again\n");
    sgx_status = ecall_feed_tcp_recv(eid, &len_to_flush, raft_conn, buf_recv, 1);
    if(sgx_status !=0){
      Debug("ecall_feed_tcp_recv failed\n");
      break;
    }
  }
  Debug("close connection\n");
  Debug("exit coroutine\n");
}


raft_peer_t* find_peer(char* ip){
  raft_peer_t* raft_peer = raft_peers;
  while(raft_peer){
    if(strcmp(raft_peer->ip, ip)==0){
      return raft_peer;
    }
    raft_peer = raft_peer->next;
  }
  return NULL;
}
coroutine void start_server(sgx_enclave_id_t eid, WOLFSSL_CTX* ctx, char* server_ip){

  struct ipaddr addr;
  int rc = ipaddr_local(&addr, server_ip, 5555, 0);
  if (rc < 0) {
    perror("Can't open listening socket");
    return;

  }
  int ls = tcp_listen(&addr, -1);
  assert( ls >= 0 );


  while(1) {
    struct ipaddr c_addr;
    int s = tcp_accept(ls, &c_addr, -1);
    assert(s >= 0);
    char* client_ip = malloc(IPADDR_MAXSTRLEN);
    ipaddr_str(&c_addr, client_ip);
    int port = ipaddr_port(&c_addr);
    Debug("Peer Connected IP address: %s:%d\n", client_ip, port);
    raft_peer_t* peer = find_peer(client_ip);
    if(peer){
      if(peer->tcp_connected ==1){
        tcp_close(s, -1);
      }else{
        Debug("one peer connected\n");
        peer->tcp_connected = 1;
        peer->is_client = 1;
        peer->socket = s;
        int rc = go(raft_conn_new(eid, ctx, peer));
        assert(rc >= 0);
      }
    }else{
      Debug("unauthorized conn\n");
      tcp_close(s, -1);
    }
  }

}

coroutine void start_client(sgx_enclave_id_t eid, WOLFSSL_CTX* ctx, raft_peer_t* peer){

  Debug("start client\n");
  struct ipaddr peer_addr;
  ipaddr_local(&peer_addr, peer->ip, peer->port, 0);
  int s = tcp_connect(&peer_addr, 0);
  if(s>0){
    peer->tcp_connected = 1;
    peer->socket = s;
    peer->is_client = 0;
    Debug("client %s connected\n", peer->ip);
    int rc = go(raft_conn_new(eid, ctx, peer));
    assert(rc>=0);
  }
}

coroutine void start_clients(sgx_enclave_id_t eid, WOLFSSL_CTX* ctx){
  while(1){
    Debug("start clients loop\n");
    raft_peer_t* raft_peer = raft_peers;
    while(raft_peer){
      if(raft_peer->tcp_connected != 1){
        start_client(eid, ctx, raft_peer);
      }
      raft_peer = raft_peer->next;
    }
    msleep(now()+2000);
  }
}


int main(int argc, char* argv[]) /* not using since just testing w/ wc_test */
{
  sgx_enclave_id_t id;
  sgx_launch_token_t t;

  int ret = 0;
  int sgx_status = 0;
  int updated = 0;

  memset(t, 0, sizeof(sgx_launch_token_t));

  sgx_status = sgx_create_enclave(ENCLAVE_FILENAME, DEBUG_VALUE, &t, &updated, &id, NULL);
  if (sgx_status != SGX_SUCCESS) {
    Error("Failed to create Enclave : error %d - %#x.\n", ret, ret);
    return 1;
  }

  //  cache_verify_buffer(id);
  WOLFSSL_CTX* ctx;
  sgx_status = ecall_setup_wolfssl_ctx(id, &ctx);

  // parse cluster config, create raft_peers and copy into enclaves
  // start raft_server
  // start other raft_clients

  if(argc != 4){
    Debug("wrong args\n");
    return -1;
  }

  char* server_ip = argv[1];

  Debug("server_ip:%s\n\n\n", server_ip);
  raft_peer_t* peer1 = malloc(sizeof(raft_peer_t));
  //  peer1->ip = argv[2];
  strcpy(peer1->ip, argv[2]);
  Debug("peer 1 ip: %s\n", peer1->ip);
  peer1->port = 5555;
  peer1->tcp_connected = 0;
  peer1->socket = -1;
  peer1->is_client = 0;

  raft_peer_t* peer2 = malloc(sizeof(raft_peer_t));
  //  peer2->ip = argv[3];
  strcpy(peer2->ip, argv[3]);
  peer2->port = 5555;
  peer2->tcp_connected = 0;
  peer2->socket = -1;
  peer2->is_client = 0;

  peer1->next = peer2;
  peer2->next = NULL;
  raft_peers = peer1;

  go(start_clients(id, ctx));
  start_server(id, ctx, server_ip);

  return 0;
}

void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
  Ocall_printf("%s", str);
}

time_t ocall_time(time_t* timer){
  return time(timer);
}
void ocall_low_res_time(int* time)
{
    struct timeval tv;
    gettimeofday (&tv, NULL);
    if(!time) return;
    *time = tv.tv_sec;
    return;
}
