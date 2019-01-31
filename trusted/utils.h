/* client-tls.h
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

#ifndef Utils_h
#define Utils_h

#include <wolfssl/ssl.h>

typedef struct{
  WOLFSSL* ssl;
  long len;
  char* data;
} response;

typedef struct raft_conn_s{
  WOLFSSL* ssl;
  int socket;
  char* buf_tcp_recv;
  char* buf_tcp_send;
  int tls_established;
  int len_buf_tcp_recv;
  int len_buf_tcp_send;
  char* buf_tls_send;
  int len_buf_tls_send;
}raft_conn_t;

#endif /* CLIENT_TLS_H */
