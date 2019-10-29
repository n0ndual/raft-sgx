#include <stdarg.h>
#include "http_parser.h"
#include <stdio.h>      /* vsnprintf */
#include "sgx_unsupported.h"
#include "logging.h"
#include "Wolfssl_Enclave_t.h"
#include "Wolfssl_Enclave.h"

#include "raftee.h"
#include "https_server.h"
#include "sgx_trts.h"
#include <sgx_tae_service.h>
#include <sgx_tkey_exchange.h>
#include <sgx_tcrypto.h>
#include "hashmap.h"

extern server_t* sv;
extern WOLFSSL_CTX* server_ctx;
extern WOLFSSL_CTX* client_ctx;

int url_cb(http_parser* parser, const char* p, size_t len){
  parser_cb_data* data = parser->data;
  data->url = (char*)malloc((len+1)*sizeof(char));
  strncpy(data->url, p, len);
  data->url[len] = '\0';
  data->len_url = len;
  Debug_enclave("url_cb: %s\n", data->url);
  return 0;
}

int message_complete_cb(http_parser* parser) {
  /* access to thread local custom_data_t struct.
       Use this access save parsed data for later use into thread local
         buffer, or communicate over socket
  */
  parser_cb_data* data = parser->data;
  data->come_on_baby = 0;
  Debug_enclave("Read and Parse Message Done\n");
  return 0;
}

int body_cb (http_parser *parser, const char *p, size_t len)
{
  parser_cb_data* data = parser->data;
  data->body = (char*)malloc((len+1) * sizeof(char));
  strncpy(data->body, p, len);
  data->body[len] = '\0';
  data->len_body = len;
  Debug_enclave("body_cb: '%s'\n", data->body);
  return 0;
}

int https_send_response(tls_connection_t* tls_conn, char* data, int len){
    char* response;
    int ret = asprintf(&response, "HTTP/1.1 200 OK\r\nContent-Length:%d\r\n\r\n%s", len-1, data);
    if(ret==-1){
      Error_enclave("asprintf oracle response error\n");
    }
    Debug_enclave("%s, https response:%s\n", tls_conn->id, response);
    tls_send(tls_conn, response, ret);
    return 0;
}

int status_entry(tls_connection_t* tls_conn, char* data, size_t len){

  // check if leader exists and if this node is leader
  raft_node_t* leader = raft_get_current_leader_node(sv->raft);
  if(!leader){
    Debug_enclave("leader not exists\n");
    char* response = "leader unavailable";
    https_send_response(tls_conn, response, strlen(response)+1);
    return 0;
  }
  if(raft_node_get_id(leader) != sv->node_id){
    Debug_enclave("redirect to leader\n");
    char* response;
    raft_connection_t* leader_conn = raft_node_get_udata(leader);
    char* ip = leader_conn->tls_conn->ip;
    int ret = asprintf(&response, "HTTP/1.1 308 Moved Permanently\r\nlocation: https://%s:%d/key\r\n\r\n", ip, 6666);
    Warn_enclave("%s response: %s", tls_conn->id, response);
    tls_send(tls_conn, response, ret);
    return 0;
  }

  if(len <16){
    Warn_enclave("%s, bad key format\n", tls_conn->id);
    return -1;
  }
  char str_term[8];
  char str_index[8];
  unsigned long int long_term;
  unsigned long int long_index;
  unsigned int term;
  unsigned int index;
  char* ending_unused;

  memcpy(str_term, data, 8);
  memcpy(str_index, data+8, 8);

  long_term = strtoul(str_term, &ending_unused, 10);
  long_index = strtoul(str_index, &ending_unused, 10);
  term = long_term;
  index = long_index;
  Debug_enclave("%s, term :%d, index:%d\n", tls_conn->id, term, index);

  /* check status */
  map_t map = sv->fsm->map;
  fsm_state_t* state;

  char* key = malloc(sizeof(char)*17);
  memcpy(key, data, 16);
  key[16]='\0';
  Debug_enclave("%s, key to search: %s, len:%d\n", tls_conn->id, key, strlen(key));
  int error = hashmap_get(map, key, (void**)(&state));
  if(error==MAP_OK){
    Debug_enclave("%s, find state, term: %0d, index: %0d, buf: %s\n", tls_conn->id,
                  state->raft_term, state->raft_index, state->data.buf);
    char* response;
    int ret = asprintf(&response, "status:%s\r\ntx_index:%d\r\n", "success", state->fsm_index);
    https_send_response(tls_conn, response, ret);
    return 0;
  }else{
    Debug_enclave("%s, key not found\n", tls_conn->id);
    https_send_response(tls_conn, "failed", 7);
  }
  //  raft_msg_entry_response_committed(sv->raft, )
  return 0;
}

int add_entry(tls_connection_t* tls_conn, char* data, size_t len, msg_entry_response_t* r){
  // check if leader exists and if this node is leader
  raft_node_t* leader = raft_get_current_leader_node(sv->raft);
  if(!leader){
    Debug_enclave("leader not exists\n");
    char* response = "leader unavailable";
    https_send_response(tls_conn, response, strlen(response)+1);
    return 0;
  }
  if(raft_node_get_id(leader) != sv->node_id){
    Debug_enclave("redirect to leader\n");
    char* response;
    raft_connection_t* leader_conn = raft_node_get_udata(leader);
    char* ip = leader_conn->tls_conn->ip;
    int ret = asprintf(&response, "HTTP/1.1 308 Moved Permanently\r\nlocation: https://%s:%d/put\r\n\r\n", ip, 6666);
    Warn_enclave("response: %s", response);
    tls_send(tls_conn, response, ret);
    return 0;
  }

  msg_entry_t entry = {};
  entry.id = 0;
  sgx_read_rand(((unsigned char*)&entry.id+1), sizeof(unsigned int)-1);
  entry.data.buf = (void*)data;
  entry.data.len = len;

  //    printf("already locked?\n");
  //    uv_mutex_lock(&sv->raft_lock);

  Debug_enclave("to write a new entry\n");
  msg_entry_response_t entry_response;
  //  int ret = raft_recv_entry(sv->raft, &entry, &entry_response);
  int ret =0;
  Debug_enclave("raft_recv_entry done, id: %08d, idx:%08d\n", entry_response.term, entry_response.idx);
  if(ret!=0){
    Debug_enclave("raft_recv_entry failed\n");
    https_send_response(tls_conn, "failed", 7);
  }else{
    char* key;
    int ret = asprintf(&key, "%08d%08d", entry_response.term, entry_response.idx);
    https_send_response(tls_conn, key, ret+1);
  }
  return 0;
}

int parse_https(char* buf_tls_recv, int len_tls_recv, https_client_t* https_client){
  https_client->len_tls_packages +1;
  char* buf_tls = https_client->buf_tls;
  size_t size_tls = https_client->size_tls;
  size_t len_tls = https_client->len_tls;
  http_parser* parser = https_client->parser;
  http_parser_settings* settings = https_client->settings;

  parser_cb_data* cb_data = parser->data;
  Debug_enclave("%s, parser come_on_baby:%d\n",
               https_client->tls_conn->id, cb_data->come_on_baby);
  len_tls += len_tls_recv;
  while(size_tls< len_tls){
    char* new_buf_tls = realloc(buf_tls, size_tls + Buffer_size);
    if(new_buf_tls == NULL){
      Error_enclave("error: realloc");
    }else{
      size_tls += Buffer_size;
      https_client->buf_tls = new_buf_tls;
    }
  }
  strncat(buf_tls, buf_tls_recv, len_tls_recv);
  Debug_enclave("%s, https request: %s\n", https_client->tls_conn->id, buf_tls);
  http_parser_execute(parser, settings, buf_tls_recv, len_tls_recv);
  Debug_enclave("%s, parse done\n", https_client->tls_conn->id);

  if(cb_data->come_on_baby){
    return -1;
  }else{
    /* Print to stdout any data the client sends */
    https_client->buf_https = cb_data->body;
    https_client->len_https = cb_data->len_body;
    https_client->url = cb_data->url;
    https_client->len_url = cb_data->len_url;
    Warn_enclave("https request: %s\n", buf_tls);
    Debug_enclave("%s, https body:\n%s\n", https_client->tls_conn->id,cb_data->body);

    // call raft add entry
    msg_entry_response_t* r = malloc(sizeof(msg_entry_response_t));
    Debug_enclave("%s, request url: %s\n", https_client->tls_conn->id, https_client->url);


    if(strncmp(https_client->url, "/put", 4)==0){
      add_entry(https_client->tls_conn, https_client->buf_https, https_client->len_https, r);
    }
    if(strncmp(https_client->url, "/key", 4)==0){
      status_entry(https_client->tls_conn, https_client->buf_https, https_client->len_https);
    }

    //    free(cb_data->body);
    free(cb_data->url);
    free(cb_data);
    free(parser);
    free(settings);
    //    free(https_client);
    return 0;
  }

  // clean-up
  //  free(raw_data);
  //  free(cb_data);
  //  free(parser);
}
