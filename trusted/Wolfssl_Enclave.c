#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */

#include "Wolfssl_Enclave_t.h"

#include "sgx_trts.h"
#include <sgx_tae_service.h>
#include <sgx_tkey_exchange.h>
#include <sgx_tcrypto.h>
#include <sgx_thread.h>

#include "logging.h"
#include "http_parser.h"
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/certs_test.h>
#include "raft/raft.h"

#define WOLFSSL_USER_IO
#define Ocall_buffer_size 65536
#define Buffer_size  4096

char* cached_verify_buffer;
long sz_cached_verify_buffer;
static sgx_thread_mutex_t global_lock = SGX_THREAD_MUTEX_INITIALIZER;

WOLFSSL_CTX* server_ctx;
WOLFSSL_CTX* client_ctx;

void printf(const char *fmt, ...)
{
    char buf[Ocall_buffer_size] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, Ocall_buffer_size, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

int sprintf(char* buf, const char *fmt, ...)
{
    va_list ap;
    int ret;
    va_start(ap, fmt);
    ret = vsnprintf(buf, Ocall_buffer_size, fmt, ap);
    va_end(ap);
    return ret;
}

time_t XTIME(time_t* timer){
  time_t time;
  ocall_time(&time, timer);
  return time;
}

static const sgx_ec256_public_t def_service_public_key = {
    {
        0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
        0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
        0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
        0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38
    },
    {
        0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
        0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
        0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
        0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06
    }

};

#define PSE_RETRIES	5	/* Arbitrary. Not too long, not too short. */

#if defined(XMALLOC_USER) || defined(XMALLOC_OVERRIDE)
    #warning verfication of heap hint pointers needed when overriding default malloc/free
#endif



#if defined(WOLFSSL_STATIC_MEMORY)
/* check on heap hint when used, aborts if pointer is not in Enclave.
 * In the default case where wolfSSL_Malloc is used the heap hint pointer is not
 * used.*/
static void checkHeapHint(WOLFSSL_CTX* ctx, WOLFSSL* ssl)
{
    WOLFSSL_HEAP_HINT* heap;
    if ((heap = (WOLFSSL_HEAP_HINT*)wolfSSL_CTX_GetHeap(ctx, ssl)) != NULL) {
        if(sgx_is_within_enclave(heap, sizeof(WOLFSSL_HEAP_HINT)) != 1)
            abort();
        if(sgx_is_within_enclave(heap->memory, sizeof(WOLFSSL_HEAP)) != 1)
            abort();
    }
}
static WOLFSSL_HEAP_HINT* HEAP_HINT;
#else
#define HEAP_HINT NULL
#endif /* WOLFSSL_STATIC_MEMORY */

void enc_wolfSSL_Debugging_ON(void)
{
    wolfSSL_Debugging_ON();
}

void enc_wolfSSL_Debugging_OFF(void)
{
    wolfSSL_Debugging_OFF();
}


int enc_wolfSSL_CTX_use_certificate_chain_buffer_format(WOLFSSL_CTX* ctx,
                                                        const unsigned char* buf, long sz, int type)
{
  if(sgx_is_within_enclave(ctx, wolfSSL_CTX_GetObjectSize()) != 1)
    abort();

#if defined(WOLFSSL_STATIC_MEMORY)
  checkHeapHint(ctx, NULL);
  #endif

  return wolfSSL_CTX_use_certificate_chain_buffer_format(ctx, buf, sz, type);

}

int enc_wolfSSL_CTX_use_certificate_buffer(WOLFSSL_CTX* ctx,
        const unsigned char* buf, long sz, int type)
{
    if(sgx_is_within_enclave(ctx, wolfSSL_CTX_GetObjectSize()) != 1)
        abort();

#if defined(WOLFSSL_STATIC_MEMORY)
    checkHeapHint(ctx, NULL);
#endif

    return wolfSSL_CTX_use_certificate_buffer(ctx, buf, sz, type);
}

int enc_wolfSSL_CTX_use_PrivateKey_buffer(WOLFSSL_CTX* ctx, const unsigned char* buf,
                                            long sz, int type)
{
    if(sgx_is_within_enclave(ctx, wolfSSL_CTX_GetObjectSize()) != 1)
        abort();

#if defined(WOLFSSL_STATIC_MEMORY)
    checkHeapHint(ctx, NULL);
#endif

    return wolfSSL_CTX_use_PrivateKey_buffer(ctx, buf, sz, type);
}

int enc_wolfSSL_CTX_gen_n_use_PrivateKey_buffer(WOLFSSL_CTX* ctx){
    if(sgx_is_within_enclave(ctx, wolfSSL_CTX_GetObjectSize()) != 1)
        abort();

#if defined(WOLFSSL_STATIC_MEMORY)
    checkHeapHint(ctx, NULL);
    HEAP_HINT = (WOLFSSL_HEAP_HINT*)wolfSSL_CTX_GetHeap(ctx, ssl);
#endif
    WC_RNG rng;
    ecc_key key;
    XMEMSET(&key, 0, sizeof(key));
    int ret = wc_InitRng_ex(&rng, HEAP_HINT, INVALID_DEVID);
    if (ret < 0) {
      abort();
    }
    ret = wc_ecc_init_ex(&key, HEAP_HINT, INVALID_DEVID);
    if (ret < 0) {
      abort();
    }
    Debug_enclave("begin make may\n");
    ret = wc_ecc_make_key(&rng, 32, &key);
    if (ret < 0) {
      abort();
    }
    Debug_enclave("make key done\n");
    unsigned char buf[121] = {0};
    ret = wc_EccKeyToDer(&key, buf, sizeof(key));
    //printf("%02X", buf);
    return wolfSSL_CTX_use_PrivateKey_buffer(ctx, buf, sizeof(buf), SSL_FILETYPE_ASN1);
}

int enc_cache_verify_buffer(const unsigned char* in,
                                       long sz)
{
  //  Debug_enclave("verify buffer size:%ld\n", sz);
  sz_cached_verify_buffer = sz;
  cached_verify_buffer = (unsigned char*)malloc(sizeof(unsigned char) * sz);
  memcpy(cached_verify_buffer, in, sz);
  return 0;
}

int LowResTimer(void) /* low_res timer */
{
    int time;
    ocall_low_res_time(&time);
    return time;
}

typedef struct raft_peer_s{
  char ip[46];
  int socket;
  int tcp_connected;
  int is_client;
  char* buf_tcp_recv;
  char* buf_tcp_send;
  int len_buf_tcp_recv;
  int len_buf_tcp_send;
  WOLFSSL* ssl;
  char* buf_tls_send;
  int len_buf_tls_send;
  int tls_established;
  struct raft_peer_s* next;
} raft_peer_t;

raft_peer_t* peers;


int NBSend(WOLFSSL* ssl, char* buf, int sz, void* ctx){
  Debug_enclave("NBSend: %d\n",sz);
  raft_peer_t* raft_conn = (raft_peer_t*)ctx;
  if(raft_conn->len_buf_tcp_send > 0){
    memcpy(raft_conn->buf_tcp_send + raft_conn->len_buf_tcp_send, buf, sz);
    raft_conn->len_buf_tcp_send = raft_conn->len_buf_tcp_send + sz;
    return sz;
  }else{
    raft_conn->len_buf_tcp_send = sz;
    memcpy(raft_conn->buf_tcp_send, buf, sz);
    return sz;
  }
}

int NBRecv(WOLFSSL* ssl, char* buf, int sz, void* ctx){
  raft_peer_t* raft_conn = (raft_peer_t*)ctx;
  if(raft_conn->len_buf_tcp_recv > 0){
    //    Debug_enclave("NBRecv read %d byte\n", raft_conn->len_buf_tcp_recv);
    memcpy(buf, raft_conn->buf_tcp_recv, 1);
    raft_conn->len_buf_tcp_recv =0;
    return 1;
  }else{
    //    Debug_enclave("NBRecv failed: want read\n");
    return WOLFSSL_CBIO_ERR_WANT_READ;
  }
}

WOLFSSL_CTX* ecall_setup_wolfssl_ctx(void){

  wolfSSL_Init();
  wolfSSL_Debugging_OFF();
  if ((server_ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method())) == NULL) {
    printf("ERROR: failed to create WOLFSSL_CTX\n");
    return NULL;
  }

  wolfSSL_CTX_use_certificate_buffer(server_ctx,
                                                     server_cert_der_2048, sizeof_server_cert_der_2048, SSL_FILETYPE_ASN1);

  wolfSSL_CTX_use_PrivateKey_buffer(server_ctx,
                                                    server_key_der_2048, sizeof_server_key_der_2048, SSL_FILETYPE_ASN1);

  wolfSSL_CTX_load_verify_buffer(server_ctx, ca_cert_der_2048, sizeof_ca_cert_der_2048, SSL_FILETYPE_ASN1);

  wolfSSL_SetIORecv(server_ctx, NBRecv);
  wolfSSL_SetIOSend(server_ctx, NBSend);


  if ((client_ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method())) == NULL) {
    printf("ERROR: failed to create WOLFSSL_CTX\n");
    return NULL;
  }

  wolfSSL_CTX_use_certificate_buffer(client_ctx,
                                                     client_cert_der_2048, sizeof_client_cert_der_2048, SSL_FILETYPE_ASN1);

  wolfSSL_CTX_use_PrivateKey_buffer(client_ctx,
                                                    client_key_der_2048, sizeof_client_key_der_2048, SSL_FILETYPE_ASN1);

  wolfSSL_CTX_load_verify_buffer(client_ctx, ca_cert_der_2048, sizeof_ca_cert_der_2048, SSL_FILETYPE_ASN1);

  wolfSSL_SetIORecv(client_ctx, NBRecv);
  wolfSSL_SetIOSend(client_ctx, NBSend);

  return server_ctx;
}

int tls_send(raft_peer_t* raft_peer, char* msg, int len_msg){
  WOLFSSL* ssl = raft_peer->ssl;
  int new_len = raft_peer->len_buf_tls_send + len_msg;
  memcpy(raft_peer->buf_tls_send + raft_peer->len_buf_tls_send, msg, len_msg);
  raft_peer->len_buf_tls_send = new_len;
  return new_len;
}

int flush_buf_tls_send(raft_peer_t* raft_peer){
  WOLFSSL* ssl = raft_peer->ssl;
  if(raft_peer->len_buf_tls_send>0){
    int ret = wolfSSL_write(raft_peer->ssl, raft_peer->buf_tls_send, raft_peer->len_buf_tls_send);
    if(ret == raft_peer->len_buf_tls_send){
      Debug_enclave("wolfssl flush succeed\n");
      memset(raft_peer->buf_tls_send, '\0', 2048);
      raft_peer->len_buf_tls_send = 0;
    }else{
      Debug_enclave("flush buf tls failed:%d %d\n", ret, wolfSSL_get_error(raft_peer->ssl, ret));
    }
    return ret;
  }
}

void* ecall_raft_peer_new(WOLFSSL_CTX* ctx, char* ip, int sz, int socket, int is_client){
  raft_peer_t* raft_peer = (raft_peer_t*)malloc(sizeof(raft_peer_t));
  WOLFSSL* ssl;
  if(is_client == 1){
    Debug_enclave("peer is a client\n");
    if ((ssl = wolfSSL_new(server_ctx)) == NULL) {
      printf("ERROR: failed to create WOLFSSL object\n");
    }
  }else{
    if ((ssl = wolfSSL_new(client_ctx)) == NULL) {
      printf("ERROR: failed to create WOLFSSL object\n");
    }
  }

  raft_peer->ssl = ssl;
  raft_peer->socket = socket;
  raft_peer->buf_tcp_recv = malloc(sizeof(char));
  raft_peer->buf_tcp_send = malloc(sizeof(char)*2048);
  raft_peer->tls_established = 0;
  raft_peer->len_buf_tcp_recv = 0;
  raft_peer->len_buf_tcp_send = 0;
  raft_peer->buf_tls_send = malloc(sizeof(char)*2048);
  raft_peer->len_buf_tls_send = 0;

  wolfSSL_SetIOWriteCtx(ssl, raft_peer);
  wolfSSL_SetIOReadCtx(ssl, raft_peer);

  if(is_client == 0){
    Debug_enclave("after new client, sned hello\n");
    tls_send(raft_peer, "hello", 6);
  }
  return (void*)raft_peer;
}

int ecall_feed_tcp_recv(void* raft_conn, const unsigned char* buf_recv, long len_recv){
  int real_len = 0;
  raft_peer_t* raft_peer = (raft_peer_t*)raft_conn;
  memcpy(raft_peer->buf_tcp_recv, buf_recv, len_recv);
  raft_peer->len_buf_tcp_recv = len_recv;
  char buf_recv_tls[1024] = {'\0'};
  int ret = wolfSSL_read(raft_peer->ssl, buf_recv_tls, sizeof(buf_recv_tls));
  if(ret == -1){
    Debug_enclave("wolfSSL_read error = %d\n", wolfSSL_get_error(raft_peer->ssl, ret));
  }
  if(ret >= 0){
    Debug_enclave("read from raft_peer %d:%s\n", raft_peer->socket, buf_recv_tls);
    if(strcmp(buf_recv_tls, "hello")==0){
      int ret = tls_send(raft_peer, "Horde is listening\n", strlen("Horde is listening\n")+1);
      Debug_enclave("wolfssl write ret: %d %d\n", ret, wolfSSL_get_error(raft_peer->ssl, ret));
    }
  }
  return raft_peer->len_buf_tcp_send;
}

int ecall_pull_tcp_send(void* raft_conn,
                        unsigned char* buf_send, long out_sz){
  raft_peer_t* raft_peer = (raft_peer_t*)raft_conn;
  flush_buf_tls_send(raft_peer);
  Debug_enclave("pull data:%d\n", raft_peer->len_buf_tcp_send);
  memcpy(buf_send, raft_peer->buf_tcp_send, out_sz);
  int ret = raft_peer->len_buf_tcp_send;
  memset(raft_peer->buf_tcp_send, '\0', 2048);
  raft_peer->len_buf_tcp_send = 0;
  return ret;
}
