#include <libdill.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
/* wolfSSL */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#define WOLFSSL_USER_IO

#define DEFAULT_PORT 11111

#define CERT_FILE "certs/server-cert.pem"
#define KEY_FILE  "certs/server-key.pem"

typedef struct ssl_ctx_s{
  WOLFSSL* ssl;
  int socket;
} ssl_ctx_t;

int MemSend(WOLFSSL* ssl, char* buf, int sz, void* ctx){
  printf("MemSend:\n");
  //  char* buf_send_tcp = ((ssl_ctx_t*)ctx)->buf_recv_tcp;
  //  memset(buf_send_tcp, '\0', 1);
  //  memcpy(((ssl_ctx_t*)ctx)->buf_send_tcp, buf, sz);
  int s = ((ssl_ctx_t*)ctx)->socket;
  int rc =  bsend(s, buf, sz, -1);
  printf("bsend end: %d\n", rc);
  return sz;
}

int MemRecv(WOLFSSL* ssl, char* buf, int sz, void* ctx){
  printf("MemRecv:\n");
  char buf_recv_tcp[1] ={'\0'};
  int s = ((ssl_ctx_t*)ctx)->socket;
  int rc = brecv(s, buf_recv_tcp, 1, -1);
  printf("brecv end: %d\n", rc);
  memcpy(buf, buf_recv_tcp, 1);
  return 1;
}

coroutine void dialog(int s, WOLFSSL_CTX* ctx) {

  WOLFSSL*     ssl;
  if ((ssl = wolfSSL_new(ctx)) == NULL) {
    fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
  }

  ssl_ctx_t ssl_ctx = {'\0'};
  ssl_ctx.ssl = ssl;
  ssl_ctx.socket = s;

  wolfSSL_SetIOWriteCtx(ssl, &ssl_ctx);
  wolfSSL_SetIOReadCtx(ssl, &ssl_ctx);

  //  wolfSSL_set_fd(ssl, s);
  //  wolfSSL_set_using_nonblock(ssl, s);
  int ret = wolfSSL_accept(ssl);
  if (ret != SSL_SUCCESS) {
    fprintf(stderr, "wolfSSL_accept error = %d\n",
            wolfSSL_get_error(ssl, 0));
  }
  printf("handshake done\n");

  while(1){
    char buf_recv_tls[256] = {'\0'};
    if (wolfSSL_read(ssl, buf_recv_tls, sizeof(buf_recv_tls)) == -1) {
      fprintf(stderr, "socket %d ERROR: failed to read\n", s);
    }
    printf("Client: %s\n", buf_recv_tls);

    char buf_send_tls[256] = "hi, raft peer!\n";

    /* Reply back to the client */
    if (wolfSSL_write(ssl, buf_send_tls, strlen(buf_send_tls)) != (int)strlen(buf_send_tls)) {
      fprintf(stderr, "ERROR: failed to write\n");
    }
  }
  //  int rc = hclose(s);
  //  assert(rc == 0);
}

int main(int argc, char *argv[]) {

    /* declare wolfSSL objects */
  WOLFSSL_CTX* ctx;

    /* Create a socket that uses an internet IPv4 address,
     * Sets the socket to be stream based (TCP),
     * 0 means choose the default protocol. */


    /* Create and initialize WOLFSSL_CTX */
  if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method())) == NULL) {
    fprintf(stderr, "ERROR: failed to create WOLFSSL_CTX\n");
    return -1;
  }

  /* Load server certificates into WOLFSSL_CTX */
  if (wolfSSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM)
      != SSL_SUCCESS) {
    fprintf(stderr, "ERROR: failed to load %s, please check the file.\n",
            CERT_FILE);
    return -1;
  }

  /* Load server key into WOLFSSL_CTX */
  if (wolfSSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM)
      != SSL_SUCCESS) {
    fprintf(stderr, "ERROR: failed to load %s, please check the file.\n",
            KEY_FILE);
    return -1;
  }
  wolfSSL_SetIORecv(ctx, MemRecv);
  wolfSSL_SetIOSend(ctx, MemSend);
  int port = 5555;
  if(argc > 1) port = atoi(argv[1]);
  struct ipaddr addr;
  int rc = ipaddr_local(&addr, NULL, port, 0);
  if (rc < 0) {
    perror("Can't open listening socket");
    return 1;

  }
  int ls = tcp_listen(&addr, -1);
  assert( ls >= 0 );

  while(1) {
    int s = tcp_accept(ls, NULL, -1);
    assert(s >= 0);
    //    s = suffix_attach(s, "\r\n", 2);
    //    assert(s >= 0);
    int cr = go(dialog(s, ctx));
    assert(cr >= 0);
  }
}
