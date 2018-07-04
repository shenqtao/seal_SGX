#include "SealEnclaveTest_u.h"
#include <errno.h>

typedef struct ms_foo_t {
	char* ms_buf;
	size_t ms_len;
} ms_foo_t;


typedef struct ms_get_public_key_t {
	char* ms_public_key_buffer;
	size_t ms_len;
} ms_get_public_key_t;

typedef struct ms_get_secret_key_t {
	char* ms_secret_key_buffer;
	size_t ms_len;
} ms_get_secret_key_t;

typedef struct ms_sigmod_sgx_t {
	char* ms_buffer;
	size_t ms_len;
	int ms_trainingSize;
	int ms_precision;
} ms_sigmod_sgx_t;

typedef struct ms_check_Index_t {
	int ms_retval;
} ms_check_Index_t;

typedef struct ms_DecreaseNoise_SGX_t {
	char* ms_buf;
	size_t ms_len;
} ms_DecreaseNoise_SGX_t;

typedef struct ms_MakeConfigure_SGX_t {
	char* ms_ConfigureBuffer;
	size_t ms_len;
} ms_MakeConfigure_SGX_t;

typedef struct ms_AddInRow_SGX_t {
	char* ms_buf;
	size_t ms_len;
	int ms_trainingSize;
	int ms_precision;
} ms_AddInRow_SGX_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	void* ms_waiter;
	void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL SealEnclaveTest_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL SealEnclaveTest_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall((const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL SealEnclaveTest_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall((const void*)ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL SealEnclaveTest_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall((const void*)ms->ms_waiter, (const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL SealEnclaveTest_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall((const void**)ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[5];
} ocall_table_SealEnclaveTest = {
	5,
	{
		(void*)SealEnclaveTest_sgx_oc_cpuidex,
		(void*)SealEnclaveTest_sgx_thread_wait_untrusted_event_ocall,
		(void*)SealEnclaveTest_sgx_thread_set_untrusted_event_ocall,
		(void*)SealEnclaveTest_sgx_thread_setwait_untrusted_events_ocall,
		(void*)SealEnclaveTest_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t foo(sgx_enclave_id_t eid, char* buf, size_t len)
{
	sgx_status_t status;
	ms_foo_t ms;
	ms.ms_buf = buf;
	ms.ms_len = len;
	status = sgx_ecall(eid, 0, &ocall_table_SealEnclaveTest, &ms);
	return status;
}

sgx_status_t generate_key_sgx(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 1, &ocall_table_SealEnclaveTest, NULL);
	return status;
}

sgx_status_t get_public_key(sgx_enclave_id_t eid, char* public_key_buffer, size_t len)
{
	sgx_status_t status;
	ms_get_public_key_t ms;
	ms.ms_public_key_buffer = public_key_buffer;
	ms.ms_len = len;
	status = sgx_ecall(eid, 2, &ocall_table_SealEnclaveTest, &ms);
	return status;
}

sgx_status_t get_secret_key(sgx_enclave_id_t eid, char* secret_key_buffer, size_t len)
{
	sgx_status_t status;
	ms_get_secret_key_t ms;
	ms.ms_secret_key_buffer = secret_key_buffer;
	ms.ms_len = len;
	status = sgx_ecall(eid, 3, &ocall_table_SealEnclaveTest, &ms);
	return status;
}

sgx_status_t sigmod_sgx(sgx_enclave_id_t eid, char* buffer, size_t len, int trainingSize, int precision)
{
	sgx_status_t status;
	ms_sigmod_sgx_t ms;
	ms.ms_buffer = buffer;
	ms.ms_len = len;
	ms.ms_trainingSize = trainingSize;
	ms.ms_precision = precision;
	status = sgx_ecall(eid, 4, &ocall_table_SealEnclaveTest, &ms);
	return status;
}

sgx_status_t check_Index(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_check_Index_t ms;
	status = sgx_ecall(eid, 5, &ocall_table_SealEnclaveTest, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t DecreaseNoise_SGX(sgx_enclave_id_t eid, char* buf, size_t len)
{
	sgx_status_t status;
	ms_DecreaseNoise_SGX_t ms;
	ms.ms_buf = buf;
	ms.ms_len = len;
	status = sgx_ecall(eid, 6, &ocall_table_SealEnclaveTest, &ms);
	return status;
}

sgx_status_t MakeConfigure_SGX(sgx_enclave_id_t eid, char* ConfigureBuffer, size_t len)
{
	sgx_status_t status;
	ms_MakeConfigure_SGX_t ms;
	ms.ms_ConfigureBuffer = ConfigureBuffer;
	ms.ms_len = len;
	status = sgx_ecall(eid, 7, &ocall_table_SealEnclaveTest, &ms);
	return status;
}

sgx_status_t AddInRow_SGX(sgx_enclave_id_t eid, char* buf, size_t len, int trainingSize, int precision)
{
	sgx_status_t status;
	ms_AddInRow_SGX_t ms;
	ms.ms_buf = buf;
	ms.ms_len = len;
	ms.ms_trainingSize = trainingSize;
	ms.ms_precision = precision;
	status = sgx_ecall(eid, 8, &ocall_table_SealEnclaveTest, &ms);
	return status;
}

