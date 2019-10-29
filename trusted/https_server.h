#include <stdarg.h>
#include "http_parser.h"
#include <stdio.h>      /* vsnprintf */
#include "Wolfssl_Enclave.h"

typedef struct https_client_s{
  tls_connection_t* tls_conn;

  char* buf_tls;
  size_t len_tls;
  size_t size_tls;
  size_t len_tls_packages;

  http_parser* parser;
  http_parser_settings* settings;
  char* buf_https;
  size_t len_https;
  char* url;
  size_t len_url;
} https_client_t;

typedef struct{
  int come_on_baby;
  char* body;
  size_t len_body;
  char* url;
  size_t len_url;
} parser_cb_data;

int parse_https(char* buf_tls_recv, int len_tls_recv, https_client_t* https_client);

int message_complete_cb(http_parser* parser);

int url_cb(http_parser* parser, const char* p, size_t len);

int body_cb (http_parser *parser, const char *p, size_t len);
