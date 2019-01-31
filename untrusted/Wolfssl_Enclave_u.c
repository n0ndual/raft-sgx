#include "Wolfssl_Enclave_u.h"
#include <errno.h>

typedef struct ms_enc_wolfSSL_CTX_use_PrivateKey_buffer_t {
	int ms_retval;
	WOLFSSL_CTX* ms_ctx;
	const unsigned char* ms_buf;
	long int ms_sz;
	int ms_type;
} ms_enc_wolfSSL_CTX_use_PrivateKey_buffer_t;

typedef struct ms_enc_wolfSSL_CTX_gen_n_use_PrivateKey_buffer_t {
	int ms_retval;
	WOLFSSL_CTX* ms_ctx;
} ms_enc_wolfSSL_CTX_gen_n_use_PrivateKey_buffer_t;

typedef struct ms_enc_wolfSSL_CTX_use_certificate_chain_buffer_format_t {
	int ms_retval;
	WOLFSSL_CTX* ms_ctx;
	const unsigned char* ms_buf;
	long int ms_sz;
	int ms_type;
} ms_enc_wolfSSL_CTX_use_certificate_chain_buffer_format_t;

typedef struct ms_enc_wolfSSL_CTX_use_certificate_buffer_t {
	int ms_retval;
	WOLFSSL_CTX* ms_ctx;
	const unsigned char* ms_buf;
	long int ms_sz;
	int ms_type;
} ms_enc_wolfSSL_CTX_use_certificate_buffer_t;

typedef struct ms_ecall_setup_wolfssl_ctx_t {
	WOLFSSL_CTX* ms_retval;
} ms_ecall_setup_wolfssl_ctx_t;

typedef struct ms_ecall_raft_peer_new_t {
	void* ms_retval;
	WOLFSSL_CTX* ms_ctx;
	char* ms_ip;
	int ms_sz;
	int ms_socket;
	int ms_is_client;
} ms_ecall_raft_peer_new_t;

typedef struct ms_ecall_feed_tcp_recv_t {
	int ms_retval;
	void* ms_raft_conn;
	const unsigned char* ms_buf_recv;
	long int ms_in_sz;
} ms_ecall_feed_tcp_recv_t;

typedef struct ms_ecall_pull_tcp_send_t {
	int ms_retval;
	void* ms_raft_conn;
	unsigned char* ms_buf_send;
	long int ms_out_sz;
} ms_ecall_pull_tcp_send_t;

typedef struct ms_sgx_ra_get_ga_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	sgx_ec256_public_t* ms_g_a;
} ms_sgx_ra_get_ga_t;

typedef struct ms_sgx_ra_proc_msg2_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	const sgx_ra_msg2_t* ms_p_msg2;
	const sgx_target_info_t* ms_p_qe_target;
	sgx_report_t* ms_p_report;
	sgx_quote_nonce_t* ms_p_nonce;
} ms_sgx_ra_proc_msg2_trusted_t;

typedef struct ms_sgx_ra_get_msg3_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint32_t ms_quote_size;
	sgx_report_t* ms_qe_report;
	sgx_ra_msg3_t* ms_p_msg3;
	uint32_t ms_msg3_size;
} ms_sgx_ra_get_msg3_trusted_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_time_t {
	time_t ms_retval;
	time_t* ms_timer;
} ms_ocall_time_t;

typedef struct ms_ocall_low_res_time_t {
	int* ms_time;
} ms_ocall_low_res_time_t;

typedef struct ms_create_session_ocall_t {
	sgx_status_t ms_retval;
	uint32_t* ms_sid;
	uint8_t* ms_dh_msg1;
	uint32_t ms_dh_msg1_size;
	uint32_t ms_timeout;
} ms_create_session_ocall_t;

typedef struct ms_exchange_report_ocall_t {
	sgx_status_t ms_retval;
	uint32_t ms_sid;
	uint8_t* ms_dh_msg2;
	uint32_t ms_dh_msg2_size;
	uint8_t* ms_dh_msg3;
	uint32_t ms_dh_msg3_size;
	uint32_t ms_timeout;
} ms_exchange_report_ocall_t;

typedef struct ms_close_session_ocall_t {
	sgx_status_t ms_retval;
	uint32_t ms_sid;
	uint32_t ms_timeout;
} ms_close_session_ocall_t;

typedef struct ms_invoke_service_ocall_t {
	sgx_status_t ms_retval;
	uint8_t* ms_pse_message_req;
	uint32_t ms_pse_message_req_size;
	uint8_t* ms_pse_message_resp;
	uint32_t ms_pse_message_resp_size;
	uint32_t ms_timeout;
} ms_invoke_service_ocall_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL Wolfssl_Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_ocall_time(void* pms)
{
	ms_ocall_time_t* ms = SGX_CAST(ms_ocall_time_t*, pms);
	ms->ms_retval = ocall_time(ms->ms_timer);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_ocall_low_res_time(void* pms)
{
	ms_ocall_low_res_time_t* ms = SGX_CAST(ms_ocall_low_res_time_t*, pms);
	ocall_low_res_time(ms->ms_time);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_create_session_ocall(void* pms)
{
	ms_create_session_ocall_t* ms = SGX_CAST(ms_create_session_ocall_t*, pms);
	ms->ms_retval = create_session_ocall(ms->ms_sid, ms->ms_dh_msg1, ms->ms_dh_msg1_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_exchange_report_ocall(void* pms)
{
	ms_exchange_report_ocall_t* ms = SGX_CAST(ms_exchange_report_ocall_t*, pms);
	ms->ms_retval = exchange_report_ocall(ms->ms_sid, ms->ms_dh_msg2, ms->ms_dh_msg2_size, ms->ms_dh_msg3, ms->ms_dh_msg3_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_close_session_ocall(void* pms)
{
	ms_close_session_ocall_t* ms = SGX_CAST(ms_close_session_ocall_t*, pms);
	ms->ms_retval = close_session_ocall(ms->ms_sid, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_invoke_service_ocall(void* pms)
{
	ms_invoke_service_ocall_t* ms = SGX_CAST(ms_invoke_service_ocall_t*, pms);
	ms->ms_retval = invoke_service_ocall(ms->ms_pse_message_req, ms->ms_pse_message_req_size, ms->ms_pse_message_resp, ms->ms_pse_message_resp_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[12];
} ocall_table_Wolfssl_Enclave = {
	12,
	{
		(void*)Wolfssl_Enclave_ocall_print_string,
		(void*)Wolfssl_Enclave_ocall_time,
		(void*)Wolfssl_Enclave_ocall_low_res_time,
		(void*)Wolfssl_Enclave_create_session_ocall,
		(void*)Wolfssl_Enclave_exchange_report_ocall,
		(void*)Wolfssl_Enclave_close_session_ocall,
		(void*)Wolfssl_Enclave_invoke_service_ocall,
		(void*)Wolfssl_Enclave_sgx_oc_cpuidex,
		(void*)Wolfssl_Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)Wolfssl_Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)Wolfssl_Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)Wolfssl_Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t enc_wolfSSL_CTX_use_PrivateKey_buffer(sgx_enclave_id_t eid, int* retval, WOLFSSL_CTX* ctx, const unsigned char* buf, long int sz, int type)
{
	sgx_status_t status;
	ms_enc_wolfSSL_CTX_use_PrivateKey_buffer_t ms;
	ms.ms_ctx = ctx;
	ms.ms_buf = buf;
	ms.ms_sz = sz;
	ms.ms_type = type;
	status = sgx_ecall(eid, 0, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_CTX_gen_n_use_PrivateKey_buffer(sgx_enclave_id_t eid, int* retval, WOLFSSL_CTX* ctx)
{
	sgx_status_t status;
	ms_enc_wolfSSL_CTX_gen_n_use_PrivateKey_buffer_t ms;
	ms.ms_ctx = ctx;
	status = sgx_ecall(eid, 1, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_CTX_use_certificate_chain_buffer_format(sgx_enclave_id_t eid, int* retval, WOLFSSL_CTX* ctx, const unsigned char* buf, long int sz, int type)
{
	sgx_status_t status;
	ms_enc_wolfSSL_CTX_use_certificate_chain_buffer_format_t ms;
	ms.ms_ctx = ctx;
	ms.ms_buf = buf;
	ms.ms_sz = sz;
	ms.ms_type = type;
	status = sgx_ecall(eid, 2, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_CTX_use_certificate_buffer(sgx_enclave_id_t eid, int* retval, WOLFSSL_CTX* ctx, const unsigned char* buf, long int sz, int type)
{
	sgx_status_t status;
	ms_enc_wolfSSL_CTX_use_certificate_buffer_t ms;
	ms.ms_ctx = ctx;
	ms.ms_buf = buf;
	ms.ms_sz = sz;
	ms.ms_type = type;
	status = sgx_ecall(eid, 3, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_setup_wolfssl_ctx(sgx_enclave_id_t eid, WOLFSSL_CTX** retval)
{
	sgx_status_t status;
	ms_ecall_setup_wolfssl_ctx_t ms;
	status = sgx_ecall(eid, 4, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_raft_peer_new(sgx_enclave_id_t eid, void** retval, WOLFSSL_CTX* ctx, char* ip, int sz, int socket, int is_client)
{
	sgx_status_t status;
	ms_ecall_raft_peer_new_t ms;
	ms.ms_ctx = ctx;
	ms.ms_ip = ip;
	ms.ms_sz = sz;
	ms.ms_socket = socket;
	ms.ms_is_client = is_client;
	status = sgx_ecall(eid, 5, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_feed_tcp_recv(sgx_enclave_id_t eid, int* retval, void* raft_conn, const unsigned char* buf_recv, long int in_sz)
{
	sgx_status_t status;
	ms_ecall_feed_tcp_recv_t ms;
	ms.ms_raft_conn = raft_conn;
	ms.ms_buf_recv = buf_recv;
	ms.ms_in_sz = in_sz;
	status = sgx_ecall(eid, 6, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_pull_tcp_send(sgx_enclave_id_t eid, int* retval, void* raft_conn, unsigned char* buf_send, long int out_sz)
{
	sgx_status_t status;
	ms_ecall_pull_tcp_send_t ms;
	ms.ms_raft_conn = raft_conn;
	ms.ms_buf_send = buf_send;
	ms.ms_out_sz = out_sz;
	status = sgx_ecall(eid, 7, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_get_ga(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, sgx_ec256_public_t* g_a)
{
	sgx_status_t status;
	ms_sgx_ra_get_ga_t ms;
	ms.ms_context = context;
	ms.ms_g_a = g_a;
	status = sgx_ecall(eid, 8, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_proc_msg2_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce)
{
	sgx_status_t status;
	ms_sgx_ra_proc_msg2_trusted_t ms;
	ms.ms_context = context;
	ms.ms_p_msg2 = p_msg2;
	ms.ms_p_qe_target = p_qe_target;
	ms.ms_p_report = p_report;
	ms.ms_p_nonce = p_nonce;
	status = sgx_ecall(eid, 9, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_get_msg3_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size)
{
	sgx_status_t status;
	ms_sgx_ra_get_msg3_trusted_t ms;
	ms.ms_context = context;
	ms.ms_quote_size = quote_size;
	ms.ms_qe_report = qe_report;
	ms.ms_p_msg3 = p_msg3;
	ms.ms_msg3_size = msg3_size;
	status = sgx_ecall(eid, 10, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

