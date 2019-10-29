#ifndef RAFTEE_WOLFSSL_H
#define RAFTEE_WOLFSSL_H

#include "sgx_trts.h"
#include <sgx_tae_service.h>
#include <sgx_tkey_exchange.h>
#include <sgx_tcrypto.h>
#include <sgx_thread.h>

#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/certs_test.h>
#include <Wolfssl_Enclave_t.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

#define Raft_protocol (0)
#define Https_protocol (1)

double current_time(void);

typedef struct tls_connection_s{
  char ip[46];
  char* id;
  int socket;
  int tcp_connected;
  int is_client;
  char* buf_tcp_recv;
  char* buf_tcp_send;
  int len_buf_tcp_recv;
  int len_tcp_to_recv;
  int len_buf_tcp_send;
  WOLFSSL* ssl;
  char* buf_tls_send;
  int len_buf_tls_send;
  int tls_established;
  void* upper_layer;
  int upper_layer_protocol;
} tls_connection_t;

#define Buffer_size  4096
#define Package_size 8192

int tls_send(tls_connection_t* tls_conn, char* msg, int len_msg);

#endif
