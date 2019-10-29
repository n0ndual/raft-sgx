#include "raftee.h"
#include <stdio.h>      /* vsnprintf */
#include "logging.h"
#include "sgx_unsupported.h"
server_t server;
server_t *sv = &server;

extern WOLFSSL_CTX* server_ctx;
extern WOLFSSL_CTX* client_ctx;

void __delete_connection(server_t* sv, raft_connection_t* conn)
{
    raft_connection_t* prev = NULL;
    if (sv->conns == conn)
        sv->conns = conn->next;
    else if (sv->conns != conn)
    {
        for (prev = sv->conns; prev->next != conn; prev = prev->next);
        if(prev->next!= NULL)
          prev->next = conn->next;
    }

    if (conn->node)
        raft_node_set_udata(conn->node, NULL);

    // TODO: make sure all resources are freed
    free(conn);
}

raft_connection_t* __find_connection(server_t* sv, const char* host, int raft_port)
{
    raft_connection_t* conn = sv->conns;
    while(1){
      if(conn){
        Debug_enclave("find conn: %s %d\n", conn->tls_conn->ip, conn->raft_port);

        if (0 == strcmp(host, conn->tls_conn->ip) &&
            conn->raft_port == raft_port){
          return conn;
        }else{
          conn = conn->next;
        }
      }else{
        break;
      }
    }
    return conn;
}

raft_connection_t* __new_connection(server_t* sv)
{
  Debug_enclave("should not be here\n");
  raft_connection_t* conn = malloc(sizeof(raft_connection_t));
  conn->next = sv->conns;
  sv->conns = conn;
  return conn;
}

/** Connect to raft peer, already connected, do nothing */
void __connect_to_peer(raft_connection_t* conn)
{

}

void __connection_set_peer(raft_connection_t* conn, char* ip, int port)
{
    conn->raft_port = port;
    if(!conn->tls_conn){
      conn->tls_conn = malloc(sizeof(tls_connection_t));
    }
    memcpy(conn->tls_conn->ip, ip, strlen(ip)+1);
    printf("Connecting to %s:%d\n", conn->tls_conn->ip, port);

}

void __connect_to_peer_at_host(raft_connection_t* conn, char* host,
                                      int port)
{
  //__connection_set_peer(conn, host, port);
    //to-do: can be deleted?
    // __connect_to_peer(conn);
}

void __peer_msg_send(tls_connection_t* tls_conn, tpl_node *tn)
{
    size_t sz;
    tpl_pack(tn, 0);
    tpl_dump(tn, TPL_GETSIZE, &sz);
    char* data = malloc(sz* sizeof(char));
    int ret = tpl_dump(tn, TPL_MEM | TPL_PREALLOCD, data, sz);
    Debug_enclave("tpl dump ret: %d, to send size:%d\n", ret, sz);
    tls_send(tls_conn, data, sz);
    tpl_free(tn);
}

/** Initiate connection if we are disconnected */
int __connect_if_needed(raft_connection_t* conn)
{
  if(conn == NULL){
    return -1;
  }
  return 0;
}

/** Raft callback for sending request vote message */
int __raft_send_requestvote(
    raft_server_t* raft,
    void *user_data,
    raft_node_t *node,
    msg_requestvote_t* m
    )
{
  Warn_enclave("send_requestvote\n");
    raft_connection_t* raft_conn = raft_node_get_udata(node);

    int e = __connect_if_needed(raft_conn);
    if (-1 == e)
        return 0;

    msg_t msg = {};
    msg.type = MSG_REQUESTVOTE,
    msg.rv = *m;
    __peer_msg_send(raft_conn->tls_conn, tpl_map("S(I$(IIII))", &msg));
    return 0;
}

/** Raft callback for sending appendentries message */
/** 没有调用__peer_msg_send，直接发送了 */
int __raft_send_appendentries(
    raft_server_t* raft,
    void *user_data,
    raft_node_t *node,
    msg_appendentries_t* m
    )
{
    raft_connection_t* raft_conn = raft_node_get_udata(node);
    if(raft_conn==NULL){
      Error_enclave("the raft_conn of node(id:%d) is null\n", raft_node_get_id(node));
      return -1;
    }
    //    int e = __connect_if_needed(raft_conn);
    //    if (-1 == e)
    //        return 0;

    msg_t msg = {};
    msg.type = MSG_APPENDENTRIES;
    msg.ae.term = m->term;
    msg.ae.prev_log_idx   = m->prev_log_idx;
    msg.ae.prev_log_term = m->prev_log_term;
    msg.ae.leader_commit = m->leader_commit;
    msg.ae.n_entries = m->n_entries;
    // if n_entries==0，it's a keep alive msg; if not, send the entries;
    __peer_msg_send(raft_conn->tls_conn, tpl_map("S(I$(IIIII))", &msg));
    Debug_enclave("append entry part 0 done\n");
    // Sending only the first one entry is safe too.
    int i =  0;
    /* appendentries with payload */
    if (0 < m->n_entries)
    {
        tpl_bin tb = {
            .sz   = m->entries[i].data.len,
            .addr = m->entries[i].data.buf
        };

        /* list of entries */
        tpl_node *tn = tpl_map("IIIB",
                &m->entries[0].id,
                &m->entries[0].term,
                &m->entries[0].type,
                &tb);
        size_t sz;
        tpl_pack(tn, 0);
        tpl_dump(tn, TPL_GETSIZE, &sz);
        char* data = malloc(sz*sizeof(char));
        tpl_dump(tn, TPL_MEM | TPL_PREALLOCD, data, sz);
        //        Debug_enclave("add entry %d to the tls package done\n", i);
        tls_send(raft_conn->tls_conn, data, sz);
        tpl_free(tn);
        i++;
        m->n_entries--;
    }
  return 0;
}

//to-do: send_leave
void __send_leave(raft_connection_t* raft_conn)
{
    /* uv_buf_t bufs[1]; */
    /* char buf[RAFT_BUFLEN]; */
    /* msg_t msg = {}; */
    /* msg.type = MSG_LEAVE; */
    /* __peer_msg_send(raft_conn->tls_conn, tpl_map("S(I)", &msg)); */
}

void __send_handshake(raft_connection_t* raft_conn)
{
    msg_t msg = {};
    msg.type = MSG_HANDSHAKE;
    msg.hs.raft_port = 5555;
    msg.hs.http_port = 8888;
    msg.hs.node_id = sv->node_id;
    __peer_msg_send(raft_conn->tls_conn, tpl_map("S(I$(IIII))", &msg));
}

int __send_leave_response(raft_connection_t* raft_conn)
{
    if (!raft_conn)
    {
        printf("no connection??\n");
        return -1;
    }
    msg_t msg = {};
    msg.type = MSG_LEAVE_RESPONSE;
    __peer_msg_send(raft_conn->tls_conn, tpl_map("S(I)", &msg));
    return 0;
}

int __send_handshake_response(raft_connection_t* raft_conn,
                                     handshake_state_e success,
                                     raft_node_t* leader)
{
    msg_t msg = {};
    msg.type = MSG_HANDSHAKE_RESPONSE;
    msg.hsr.success = success;
    msg.hsr.leader_port = 5555;
    msg.hsr.node_id = sv->node_id;

    /* allow the peer to redirect to the leader */
    if (leader)
    {
        raft_connection_t* leader_conn = raft_node_get_udata(leader);
        if (leader_conn)
        {
            msg.hsr.leader_port = leader_conn->raft_port;
            //            snprintf(msg.hsr.leader_host, IP_STR_LEN, "%s",
            //       inet_ntoa(leader_conn->addr.sin_addr));
            Debug_enclave("send handshake response\n");
        }
    }

    msg.hsr.http_port = 8888;

    __peer_msg_send(raft_conn->tls_conn, tpl_map("S(I$(IIIIs))", &msg));

    return 0;
}

/** Deserialize a single log entry from appendentries message */
void __deserialize_appendentries_payload(msg_entry_t* out,
                                                tls_connection_t* conn,
                                                void *img,
                                                size_t sz)
{
    tpl_bin tb;
    tpl_node *tn = tpl_map(tpl_peek(TPL_MEM, img, sz),
                           &out->id,
                           &out->term,
                           &out->type,
                           &tb);
    tpl_load(tn, TPL_MEM, img, sz);
    tpl_unpack(tn, 0);
    out->data.buf = tb.addr;
    out->data.len = tb.sz;
}

/** Parse raft peer traffic using binary protocol, and respond to message */
int __deserialize_and_handle_msg(void *img, size_t sz, void * void_raft_conn)
{
    raft_node_id_t leader_id = raft_get_current_leader(sv->raft);
    raft_connection_t* raft_conn = (raft_connection_t*)void_raft_conn;
    tls_connection_t* tls_conn = raft_conn->tls_conn;

    int e;

    /* special case: handle appendentries payload */
    if (0 < raft_conn->n_expected_entries)
    {
        Debug_enclave("recv one expected_entry\n");
        msg_entry_t entry;

        __deserialize_appendentries_payload(&entry, tls_conn, img, sz);

        raft_conn->ae.ae.entries = &entry;
        msg_t msg = { .type = MSG_APPENDENTRIES_RESPONSE };
        Debug_enclave("recv one entry, sender is null? %d\n", raft_conn->node==NULL);
        e = raft_recv_appendentries(sv->raft, raft_conn->node, &raft_conn->ae.ae, &msg.aer);
        Warn_enclave("ae response, t: %ld, succ: %d, current_idx: %ld, firs_i: %ld\n",
                     msg.aer.term,
                     msg.aer.success,
                     msg.aer.current_idx,
                     msg.aer.first_idx);
        __peer_msg_send(raft_conn->tls_conn, tpl_map("S(I$(IIII))", &msg));

        raft_conn->n_expected_entries = 0;
        return 0;
    }

    msg_t m;
    /* deserialize message */
    tpl_node *tn = tpl_map(tpl_peek(TPL_MEM, img, sz), &m);
    tpl_load(tn, TPL_MEM, img, sz);
    tpl_unpack(tn, 0);

    switch (m.type)
    {
    case MSG_HANDSHAKE:
      {
        raft_conn->connection_status = CONNECTED;
        raft_conn->http_port = m.hs.http_port;
        raft_conn->raft_port = m.hs.raft_port;

        raft_node_t* leader = raft_get_current_leader_node(sv->raft);

        /* Is this peer in our configuration already? */
        raft_node_t* node = raft_get_node(sv->raft, m.hs.node_id);
        if (node)
        {
          // when node successfully handshake with leader, its connection is linked with raft_node
            Error_enclave("Danger! leader exists, recv handshake from a known node\n");
            raft_node_set_udata(node, raft_conn);
            raft_conn->node = node;
        }

        if (!leader)
        {
          Error_enclave("leader does not exists\n");
            return __send_handshake_response(raft_conn, HANDSHAKE_FAILURE, NULL);
        }else if (raft_node_get_id(leader) != sv->node_id){
          Error_enclave("non-leader recv handshake from peer\n");
          return __send_handshake_response(raft_conn, HANDSHAKE_FAILURE, leader);
        }else{
          Error_enclave("add new follower, initially non_voting\n");
          int e = __append_cfg_change(sv, RAFT_LOGTYPE_ADD_NONVOTING_NODE,
                                      tls_conn->ip,
                                      m.hs.raft_port, m.hs.http_port,
                                      m.hs.node_id);
          if (0 != e)
            return __send_handshake_response(raft_conn, HANDSHAKE_FAILURE, NULL);
          return __send_handshake_response(raft_conn, HANDSHAKE_SUCCESS, NULL);
        }
      }
      break;
    case MSG_HANDSHAKE_RESPONSE:
        if (0 == m.hsr.success)
        {
          Warn_enclave("receive failed handshake_response\n");
          /* raft_conn->http_port = m.hsr.http_port; */

          /* /\* We're being redirected to the leader *\/ */
          /* if (m.hsr.leader_port) */
          /*   { */
          /*     raft_connection_t* leader_conn = */
          /*       __find_connection(sv, m.hsr.leader_host, m.hsr.leader_port); */
          /*     if (!leader_conn) */
          /*       { */
          /*         // in this version, these code should not run. */
          /*         leader_conn = __new_connection(sv); */
          /*         Debug_enclave("Redirecting to %s:%d...\n", */
          /*                       m.hsr.leader_host, m.hsr.leader_port); */
          /*         __connect_to_peer_at_host(leader_conn, m.hsr.leader_host, */
          /*                                   m.hsr.leader_port); */
          /*       } */
          /*   } */
          return -1;
        }else{
            Debug_enclave("Connected to leader: %s:%d\n",
                 tls_conn->ip, raft_conn->raft_port);
        }
        break;
    case MSG_LEAVE:
        {
          Warn_enclave("receive raft_leave\n");
        if (!raft_conn->node)
        {
            Error_enclave("ERROR: no node\n");
            return 0;
        }
        int e = __append_cfg_change(sv, RAFT_LOGTYPE_REMOVE_NODE,
                                tls_conn->ip,
                                raft_conn->raft_port,
                                raft_conn->http_port,
                                raft_node_get_id(raft_conn->node));
        if (0 != e)
            Error_enclave("ERROR: Leave request failed\n");
        }
        break;
    case MSG_LEAVE_RESPONSE:
        Debug_enclave("Shutdown complete. Quitting...\n");
        break;
    case MSG_REQUESTVOTE:
    {
      Warn_enclave("recv msg_request_vote\n");
        msg_t msg = { .type = MSG_REQUESTVOTE_RESPONSE };
        e = raft_recv_requestvote(sv->raft, raft_conn->node, &m.rv, &msg.rvr);
        __peer_msg_send(tls_conn, tpl_map("S(I$(II))", &msg));
    }
    break;
    case MSG_REQUESTVOTE_RESPONSE:
      Warn_enclave("recv requestvote_response\n");
        e = raft_recv_requestvote_response(sv->raft, raft_conn->node, &m.rvr);
        break;
    case MSG_APPENDENTRIES:
      if(leader_id!= sv->node_id){
        /* special case: get ready to handle appendentries payload */
        if (0 < m.ae.n_entries)
        {
          Debug_enclave("recv appendentries, not heartbeat, expected: %d\n", m.ae.n_entries);
          //            raft_conn->n_expected_entries = m.ae.n_entries;
            raft_conn->n_expected_entries = 1;
            memcpy(&raft_conn->ae, &m, sizeof(msg_t));
            //to-do: have to set ae.ae.n_expected_entries to 1;
            raft_conn->ae.ae.n_entries = 1;
            return 0;
        }

        /* this is a keep alive message */
        Warn_enclave("recv appendentries, heartbeat\n");
        msg_t msg = { .type = MSG_APPENDENTRIES_RESPONSE };
        e = raft_recv_appendentries(sv->raft, raft_conn->node, &m.ae, &msg.aer);
        __peer_msg_send(tls_conn, tpl_map("S(I$(IIII))", &msg));
        break;
      }else{
        Error_enclave("bad msg_appendentries, will not respond to it\n");
      }
    case MSG_APPENDENTRIES_RESPONSE:
        raft_recv_appendentries_response(sv->raft, raft_conn->node, &m.aer);
        break;
    default:
        Error_enclave("unknown msg\n");
    }
    return 0;
}

int parse_raft(raft_connection_t* raft_conn, char* data, int sz){
    tpl_gather(TPL_GATHER_MEM, data, sz, &raft_conn->gt,
                   __deserialize_and_handle_msg, raft_conn);
}

int __append_cfg_change(server_t* sv,
                               raft_logtype_e change_type,
                               char* host,
                               int raft_port,
                               int http_port,
                               raft_node_id_t node_id)
{
    entry_cfg_change_t *change = calloc(1, sizeof(entry_cfg_change_t));
    change->raft_port = raft_port;
    change->http_port = http_port;
    change->node_id = node_id;
    memcpy(change->host, host, strlen(host)+1);
    change->host[IP_STR_LEN - 1] = 0;

    msg_entry_t* entry = malloc(sizeof(msg_entry_t));
    sgx_read_rand((unsigned char*)&entry->id, sizeof(raft_entry_id_t));
    entry->data.buf = (void*)change;
    entry->data.len = sizeof(*change);
    entry->type = change_type;
    msg_entry_response_t r;
    int e = raft_recv_entry(sv->raft, entry, &r);
    if (0 != e)
        return -1;
    return 0;
}


int ensure_capacity(fsm_t* fsm){
  Debug_enclave("count: %d, capcacity:%d\n", fsm->count, fsm->capacity);
  if( fsm->count >= (fsm->capacity-1)){
    fsm->capacity = fsm->capacity *2;
    fsm->fsm_states = realloc(fsm->fsm_states, fsm->capacity * sizeof(fsm_state_t));
  }
  return 0;
}

/** Raft callback for applying an entry to the finite state machine */
/** leader need to deal with follower leaving entry **/
int __raft_applylog(
    raft_server_t* raft,
    void *udata,
    raft_entry_t *ety,
    raft_index_t ety_index
    )
{
    if (raft_entry_is_cfg_change(ety))
    {
        entry_cfg_change_t *change = ety->data.buf;
        if (RAFT_LOGTYPE_REMOVE_NODE != ety->type || !raft_is_leader(sv->raft))
          return 0;
        //to-do: handle DEMOTE and REMOVE

        // apply a REMOVE_NODE log, leader need to send a leave_response to the leaving node
        // the leaving node need to deal with the leave_response message
        // the other nodes just delete the connection to the leaving node.
        raft_connection_t* conn = __find_connection(sv, change->host, change->raft_port);
        __send_leave_response(conn);
        return 0;
    }else{
      Warn_enclave("apply entry to state machine, index:%ld\n", ety_index);
      fsm_t* fsm = sv->fsm;
      ensure_capacity(fsm);
      fsm_state_t* curr_state = &fsm->fsm_states[fsm->count];
      char* key;
      int ret = asprintf(&key, "%08d%08d", ety->term, ety_index);
      Debug_enclave("key len:%d\n",ret);

      curr_state->raft_id = ety->id;
      curr_state->raft_term= ety->term;
      curr_state->raft_index = ety_index;
      curr_state->fsm_key = key;
      curr_state->fsm_index = fsm->count+1;
      curr_state->data = ety->data;

      // put into map
      Debug_enclave("key len: %d, term: %d, index: %d\n", strlen(curr_state->fsm_key), curr_state->raft_term, curr_state->raft_index);

      int error = hashmap_put(fsm->map, curr_state->fsm_key, curr_state);
      if(error!=MAP_OK){
        Error_enclave("failed to put one entry into fsm, key: %s\n", curr_state->fsm_key);
      }
      fsm->count++;
      return 0;
    }
}

/** Raft callback for saving term field to disk.
 * This only returns when change has been made to disk. */
int __raft_persist_term(
    raft_server_t* raft,
    void *user_data,
    raft_term_t current_term,
    raft_node_id_t vote
    )
{
    Warn_enclave("__raft_persist_term\n");
    return 0;
}

/** Raft callback for saving voted_for field to disk.
 * This only returns when change has been made to disk. */
int __raft_persist_vote(
    raft_server_t* raft,
    void *udata,
    const int voted_for
    )
{
    Warn_enclave("__raft_persist_vote");
    return 0;
}

/** Raft callback for displaying debugging information */
void __raft_log(raft_server_t* raft, raft_node_t* node, void *udata,
                const char *buf)
{
    Warn_enclave("raft: %s\n", buf);
}

/** Raft callback for appending an item to the log */
/** the FSM of raft itself. If it is a cfg_change log, something must be done.*/
/** need to be persisted into hard drive? */
int __raft_logentry_offer(
    raft_server_t* raft,
    void *udata,
    raft_entry_t *ety,
    raft_index_t ety_idx
    )
{
  Debug_enclave("will do nothing\n");
  return 0;
}

/** Raft callback for removing the first entry from the log
 * @note this is provided to support log compaction in the future */
int __raft_logentry_poll(
    raft_server_t* raft,
    void *udata,
    raft_entry_t *entry,
    raft_index_t ety_idx
    )
{
    Warn_enclave("__raft_logentry_poll\n");
    return 0;
}

/** Raft callback for deleting the most recent entry from the log.
 * This happens when an invalid leader finds a valid leader and has to delete
 * superseded log entries. */
int __raft_logentry_pop(
    raft_server_t* raft,
    void *udata,
    raft_entry_t *entry,
    raft_index_t ety_idx
    )
{
    Warn_enclave("__raft_logentry_pop\n");
    return 0;
}

/** non-voting node now has enough logs to be able to vote.
 * Append a finalization cfg log entry. */
int __raft_node_has_sufficient_logs(
    raft_server_t* raft,
    void *user_data,
    raft_node_t* node)
{
  raft_connection_t* conn = raft_node_get_udata(node);
  __append_cfg_change(sv, RAFT_LOGTYPE_ADD_NODE,
                      conn->tls_conn->ip,
                      conn->raft_port,
                      conn->http_port,
                      raft_node_get_id(conn->node));
  return 0;
}

int __raft_send_snapshot(
    raft_server_t* raft,
    void *user_data,
    raft_node_t* node){
  Warn_enclave("send snapshot\n");
  return 0;
}

int __raft_log_clear(
    raft_server_t* raft,
    void *udata,
    raft_entry_t *entry,
    raft_index_t ety_idx
    )
{
    Warn_enclave("__raft_log_clear\n");
    return 0;
}

int __raft_log_get_node_id(
    raft_server_t* raft,
    void *udata,
    raft_entry_t *entry,
    raft_index_t ety_idx
    )
{
  entry_cfg_change_t* change = (entry_cfg_change_t*)entry->data.buf;
  Debug_enclave("cfg_change_entry,  node_id: %d\n", change->node_id);
  int id = change->node_id;
  return id;
}

void __raft_notify_membership_event(
    raft_server_t* raft,
    void *user_data,
    raft_node_t *node,
    raft_entry_t *entry,
    raft_membership_e type
    )
{
  if(type==RAFT_MEMBERSHIP_ADD){
    raft_node_id_t node_id = raft_node_get_id(node);
    if(sv->node_id == node_id){
      raft_node_set_udata(node, NULL);
    }else{
      entry_cfg_change_t* change = (entry_cfg_change_t*)entry->data.buf;
      Warn_enclave("change node_ip: %s\n", change->host);
      raft_connection_t* conn = __find_connection(sv, change->host, change->raft_port);
      Warn_enclave("found conn==NULL?%d\n", conn == NULL);
      conn->node = node;
      Warn_enclave("find out target conn: ip:%s\n", conn->tls_conn->ip);
      raft_node_set_udata(node, conn);
    }
  }
}

raft_cbs_t raft_funcs = {
    .send_requestvote            = __raft_send_requestvote,
    .send_appendentries          = __raft_send_appendentries,
    .send_snapshot               = __raft_send_snapshot,
    .applylog                    = __raft_applylog,
    .persist_vote                = __raft_persist_vote,
    .persist_term                = __raft_persist_term,
    .log_offer                   = __raft_logentry_offer,
    .log_poll                    = __raft_logentry_poll,
    .log_pop                     = __raft_logentry_pop,
    .log_clear                   = __raft_log_clear,
    .log_get_node_id             = __raft_log_get_node_id,
    .node_has_sufficient_logs    = __raft_node_has_sufficient_logs,
    .notify_membership_event     = __raft_notify_membership_event,
    .log                         = __raft_log,
};

int ecall_raft_setup(){
    memset(sv, 0, sizeof(server_t));
    sv->raft = raft_new();
    raft_set_callbacks(sv->raft, &raft_funcs, sv);
    raft_node_id_t node_id;
    sgx_read_rand((unsigned char*)&node_id, sizeof(raft_node_id_t));
    Debug_enclave("node_id: %d\n=n", node_id);
    sv->node_id = node_id;

    // non_voting
    raft_add_non_voting_node(sv->raft, NULL, sv->node_id, 1);
    fsm_t* fsm = malloc(sizeof(fsm_t));
    fsm->capacity = 1024;
    fsm->count = 0;
    fsm->fsm_states = calloc(fsm->capacity, sizeof(fsm_state_t));
    fsm->map = hashmap_new();
    sv->fsm = fsm;

    // set election timeout, must be bigger than Period_msec.
    raft_set_election_timeout(sv->raft, 10000);
}

int ecall_raft_become_leader(){
    raft_become_leader(sv->raft);
    __append_cfg_change(sv, RAFT_LOGTYPE_ADD_NODE,
                        "192.168.2.101",
                        5555,
                        6666,
                        sv->node_id);
    raft_set_commit_idx(sv->raft, 1);
    raft_apply_all(sv->raft);
}

int ecall_raft_periodic(){
    // 这个定时函数可能触发raft 节点的保存提交，重新选举
  Warn_enclave("periodic, raft_id: %d, num_voting_nodes: %d, current_leader:%d\n",
               sv->node_id,
               raft_get_num_voting_nodes(sv->raft),
               raft_get_current_leader(sv->raft));
  raft_periodic(sv->raft, PERIOD_MSEC);
  // apply all those entry that has been commited but not applied yet.
  raft_apply_all(sv->raft);

}
