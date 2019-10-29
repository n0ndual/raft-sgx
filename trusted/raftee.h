#include "raft/raft.h"
#include "raft/raft_private.h"
#include "hashmap.h"
#include "tpl/tpl.h"
#include "Wolfssl_Enclave.h"

#define IPV4_STR_LEN 3 * 4 + 3 + 1
#define IP_STR_LEN IPV4_STR_LEN

#define PERIOD_MSEC 1000

typedef enum {
    HANDSHAKE_FAILURE,
    HANDSHAKE_SUCCESS,
} handshake_state_e;

/** Message types used for peer to peer traffic
 * These values are used to identify message types during deserialization */
typedef enum
{
    /** Handshake is a special non-raft message type
     * We send a handshake so that we can identify ourselves to our peers */
    MSG_HANDSHAKE,
    /** Successful responses mean we can start the Raft periodic callback */
    MSG_HANDSHAKE_RESPONSE,
    /** Tell leader we want to leave the cluster */
    /* When instance is ctrl-c'd we have to gracefuly disconnect */
    MSG_LEAVE,
    /* Receiving a leave response means we can shutdown */
    MSG_LEAVE_RESPONSE,
    MSG_REQUESTVOTE,
    MSG_REQUESTVOTE_RESPONSE,
    MSG_APPENDENTRIES,
    MSG_APPENDENTRIES_RESPONSE,
} peer_message_type_e;

/** Peer protocol handshake
 * Send handshake after connecting so that our peer can identify us */
typedef struct
{
    int raft_port;
    int http_port;
    raft_node_id_t node_id;
} msg_handshake_t;

typedef struct
{
    int success;

    /* leader's Raft port */
    int leader_port;

    /* the responding node's HTTP port */
    int http_port;

    /* my Raft node ID.
     * Sometimes we don't know who we did the handshake with */
    raft_node_id_t node_id;

    char leader_host[IP_STR_LEN];
} msg_handshake_response_t;

/** Add/remove Raft peer */
typedef struct
{
    int raft_port;
    int http_port;
    raft_node_id_t node_id;
    char host[IP_STR_LEN];
} entry_cfg_change_t;

typedef struct
{
    int type;
    union
    {
        msg_handshake_t hs;
        msg_handshake_response_t hsr;
        msg_requestvote_t rv;
        msg_requestvote_response_t rvr;
        msg_appendentries_t ae;
        msg_appendentries_response_t aer;
    };
    int padding[100];
} msg_t;

typedef enum
{
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
} conn_status_e;

typedef struct raft_connection_s raft_connection_t;
struct raft_connection_s{

  tls_connection_t* tls_conn;

  int raft_port;

  int http_port;

  raft_connection_t* next;

  /* gather TPL message */
  tpl_gather_t *gt;

  /* tell if we need to connect or not */
  conn_status_e connection_status;

  /* peer's raft node_idx */
  raft_node_t* node;

  /* number of entries currently expected.
   * this counts down as we consume entries */
  int n_expected_entries;

  /* remember most recent append entries msg, we refer to this msg when we
   * finish reading the log entries.
   * used in tandem with n_expected_entries */
  msg_t ae;
};

//raft_connection_t* peers;

typedef struct
{
  char* fsm_key;
  unsigned int raft_id;
  unsigned int raft_term;
  unsigned int raft_index;
  unsigned int fsm_index;
  raft_entry_data_t data;
} fsm_state_t;

typedef fsm_state_t transaction_t;

typedef struct
{
  unsigned long capacity;
  unsigned long count;
  fsm_state_t* fsm_states;
  map_t map;
} fsm_t;

typedef struct
{
  /* the server's node ID */
  raft_node_id_t node_id;

  raft_server_t* raft;

  /* Link list of peer connections */
  raft_connection_t* conns;

  /* finit state machine */
  fsm_t* fsm;

} server_t;


/** function definitions */
void __send_handshake(raft_connection_t* conn);

void __peer_msg_send(tls_connection_t* conn, tpl_node *tn);

int parse_raft(raft_connection_t* conn, char* data, int sz);

int __append_cfg_change(server_t* sv,
                               raft_logtype_e change_type,
                               char* host,
                               int raft_port,
                               int http_port,
                               raft_node_id_t node_id);
