#include "SealEnclaveTest_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


typedef struct ms_set_public_key_t {
	int ms_client_id;
	char* ms_public_key_buffer;
	size_t ms_len;
} ms_set_public_key_t;

typedef struct ms_set_secret_key_t {
	int ms_client_id;
	char* ms_secret_key_buffer;
	size_t ms_len;
} ms_set_secret_key_t;

typedef struct ms_sigmod_sgx_t {
	int ms_client_id;
	char* ms_buffer;
	size_t ms_len;
	int ms_trainingSize;
	int ms_precision;
} ms_sigmod_sgx_t;

typedef struct ms_check_Index_t {
	int ms_retval;
} ms_check_Index_t;

typedef struct ms_DecreaseNoise_SGX_t {
	int ms_client_id;
	char* ms_buf;
	size_t ms_len;
} ms_DecreaseNoise_SGX_t;

typedef struct ms_MakeConfigure_SGX_t {
	int ms_client_id;
	char* ms_polymod;
	int ms_polymodlen;
	char* ms_coefmod;
	int ms_coefmodlen;
	char* ms_plainmod;
	int ms_plainmodlen;
} ms_MakeConfigure_SGX_t;

typedef struct ms_AddInRow_SGX_t {
	char* ms_buf;
	size_t ms_len;
	int ms_trainingSize;
	int ms_precision;
} ms_AddInRow_SGX_t;

typedef struct ms_ocall_print_t {
	char* ms_str;
} ms_ocall_print_t;

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

static sgx_status_t SGX_CDECL sgx_set_public_key(void* pms)
{
	ms_set_public_key_t* ms = SGX_CAST(ms_set_public_key_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_public_key_buffer = ms->ms_public_key_buffer;
	size_t _tmp_len = ms->ms_len;
	size_t _len_public_key_buffer = _tmp_len;
	char* _in_public_key_buffer = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_set_public_key_t));
	CHECK_UNIQUE_POINTER(_tmp_public_key_buffer, _len_public_key_buffer);

	if (_tmp_public_key_buffer != NULL) {
		_in_public_key_buffer = (char*)malloc(_len_public_key_buffer);
		if (_in_public_key_buffer == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_public_key_buffer, _tmp_public_key_buffer, _len_public_key_buffer);
	}
	set_public_key(ms->ms_client_id, _in_public_key_buffer, _tmp_len);
err:
	if (_in_public_key_buffer) free(_in_public_key_buffer);

	return status;
}

static sgx_status_t SGX_CDECL sgx_set_secret_key(void* pms)
{
	ms_set_secret_key_t* ms = SGX_CAST(ms_set_secret_key_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_secret_key_buffer = ms->ms_secret_key_buffer;
	size_t _tmp_len = ms->ms_len;
	size_t _len_secret_key_buffer = _tmp_len;
	char* _in_secret_key_buffer = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_set_secret_key_t));
	CHECK_UNIQUE_POINTER(_tmp_secret_key_buffer, _len_secret_key_buffer);

	if (_tmp_secret_key_buffer != NULL) {
		_in_secret_key_buffer = (char*)malloc(_len_secret_key_buffer);
		if (_in_secret_key_buffer == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_secret_key_buffer, _tmp_secret_key_buffer, _len_secret_key_buffer);
	}
	set_secret_key(ms->ms_client_id, _in_secret_key_buffer, _tmp_len);
err:
	if (_in_secret_key_buffer) free(_in_secret_key_buffer);

	return status;
}

static sgx_status_t SGX_CDECL sgx_sigmod_sgx(void* pms)
{
	ms_sigmod_sgx_t* ms = SGX_CAST(ms_sigmod_sgx_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_buffer = ms->ms_buffer;
	size_t _tmp_len = ms->ms_len;
	size_t _len_buffer = _tmp_len;
	char* _in_buffer = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_sigmod_sgx_t));
	CHECK_UNIQUE_POINTER(_tmp_buffer, _len_buffer);

	if (_tmp_buffer != NULL) {
		_in_buffer = (char*)malloc(_len_buffer);
		if (_in_buffer == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_buffer, _tmp_buffer, _len_buffer);
	}
	sigmod_sgx(ms->ms_client_id, _in_buffer, _tmp_len, ms->ms_trainingSize, ms->ms_precision);
err:
	if (_in_buffer) {
		memcpy(_tmp_buffer, _in_buffer, _len_buffer);
		free(_in_buffer);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_check_Index(void* pms)
{
	ms_check_Index_t* ms = SGX_CAST(ms_check_Index_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_check_Index_t));

	ms->ms_retval = check_Index();


	return status;
}

static sgx_status_t SGX_CDECL sgx_DecreaseNoise_SGX(void* pms)
{
	ms_DecreaseNoise_SGX_t* ms = SGX_CAST(ms_DecreaseNoise_SGX_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_buf = ms->ms_buf;
	size_t _tmp_len = ms->ms_len;
	size_t _len_buf = _tmp_len;
	char* _in_buf = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_DecreaseNoise_SGX_t));
	CHECK_UNIQUE_POINTER(_tmp_buf, _len_buf);

	if (_tmp_buf != NULL) {
		_in_buf = (char*)malloc(_len_buf);
		if (_in_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_buf, _tmp_buf, _len_buf);
	}
	DecreaseNoise_SGX(ms->ms_client_id, _in_buf, _tmp_len);
err:
	if (_in_buf) {
		memcpy(_tmp_buf, _in_buf, _len_buf);
		free(_in_buf);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_MakeConfigure_SGX(void* pms)
{
	ms_MakeConfigure_SGX_t* ms = SGX_CAST(ms_MakeConfigure_SGX_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_polymod = ms->ms_polymod;
	int _tmp_polymodlen = ms->ms_polymodlen;
	size_t _len_polymod = _tmp_polymodlen;
	char* _in_polymod = NULL;
	char* _tmp_coefmod = ms->ms_coefmod;
	int _tmp_coefmodlen = ms->ms_coefmodlen;
	size_t _len_coefmod = _tmp_coefmodlen;
	char* _in_coefmod = NULL;
	char* _tmp_plainmod = ms->ms_plainmod;
	int _tmp_plainmodlen = ms->ms_plainmodlen;
	size_t _len_plainmod = _tmp_plainmodlen;
	char* _in_plainmod = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_MakeConfigure_SGX_t));
	CHECK_UNIQUE_POINTER(_tmp_polymod, _len_polymod);
	CHECK_UNIQUE_POINTER(_tmp_coefmod, _len_coefmod);
	CHECK_UNIQUE_POINTER(_tmp_plainmod, _len_plainmod);

	if (_tmp_polymod != NULL) {
		_in_polymod = (char*)malloc(_len_polymod);
		if (_in_polymod == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_polymod, _tmp_polymod, _len_polymod);
	}
	if (_tmp_coefmod != NULL) {
		_in_coefmod = (char*)malloc(_len_coefmod);
		if (_in_coefmod == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_coefmod, _tmp_coefmod, _len_coefmod);
	}
	if (_tmp_plainmod != NULL) {
		_in_plainmod = (char*)malloc(_len_plainmod);
		if (_in_plainmod == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_plainmod, _tmp_plainmod, _len_plainmod);
	}
	MakeConfigure_SGX(ms->ms_client_id, _in_polymod, _tmp_polymodlen, _in_coefmod, _tmp_coefmodlen, _in_plainmod, _tmp_plainmodlen);
err:
	if (_in_polymod) free(_in_polymod);
	if (_in_coefmod) free(_in_coefmod);
	if (_in_plainmod) free(_in_plainmod);

	return status;
}

static sgx_status_t SGX_CDECL sgx_AddInRow_SGX(void* pms)
{
	ms_AddInRow_SGX_t* ms = SGX_CAST(ms_AddInRow_SGX_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_buf = ms->ms_buf;
	size_t _tmp_len = ms->ms_len;
	size_t _len_buf = _tmp_len;
	char* _in_buf = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_AddInRow_SGX_t));
	CHECK_UNIQUE_POINTER(_tmp_buf, _len_buf);

	if (_tmp_buf != NULL) {
		_in_buf = (char*)malloc(_len_buf);
		if (_in_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_buf, _tmp_buf, _len_buf);
	}
	AddInRow_SGX(_in_buf, _tmp_len, ms->ms_trainingSize, ms->ms_precision);
err:
	if (_in_buf) {
		memcpy(_tmp_buf, _in_buf, _len_buf);
		free(_in_buf);
	}

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[7];
} g_ecall_table = {
	7,
	{
		{(void*)(uintptr_t)sgx_set_public_key, 0},
		{(void*)(uintptr_t)sgx_set_secret_key, 0},
		{(void*)(uintptr_t)sgx_sigmod_sgx, 0},
		{(void*)(uintptr_t)sgx_check_Index, 0},
		{(void*)(uintptr_t)sgx_DecreaseNoise_SGX, 0},
		{(void*)(uintptr_t)sgx_MakeConfigure_SGX, 0},
		{(void*)(uintptr_t)sgx_AddInRow_SGX, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[6][7];
} g_dyn_entry_table = {
	6,
	{
		{0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_t);
	void *__tmp = NULL;

	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_t));

	if (str != NULL && sgx_is_within_enclave(str, _len_str)) {
		ms->ms_str = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_str);
		memcpy((void*)ms->ms_str, str, _len_str);
	} else if (str == NULL) {
		ms->ms_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(0, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(*cpuinfo);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	ocalloc_size += (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) ? _len_cpuinfo : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));

	if (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		memcpy(ms->ms_cpuinfo, cpuinfo, _len_cpuinfo);
	} else if (cpuinfo == NULL) {
		ms->ms_cpuinfo = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(1, ms);

	if (cpuinfo) memcpy((void*)cpuinfo, ms->ms_cpuinfo, _len_cpuinfo);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));

	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(2, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	status = sgx_ocall(3, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(4, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(*waiters);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) ? _len_waiters : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));

	if (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) {
		ms->ms_waiters = (void**)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		memcpy((void*)ms->ms_waiters, waiters, _len_waiters);
	} else if (waiters == NULL) {
		ms->ms_waiters = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(5, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

