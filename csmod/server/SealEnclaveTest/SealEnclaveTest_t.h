#ifndef SEALENCLAVETEST_T_H__
#define SEALENCLAVETEST_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


void set_public_key(int client_id, char* public_key_buffer, size_t len);
void set_secret_key(int client_id, char* secret_key_buffer, size_t len);
void sigmod_sgx(int client_id, char* buffer, size_t len, int trainingSize, int precision);
int check_Index();
void DecreaseNoise_SGX(int client_id, char* buf, size_t len);
void MakeConfigure_SGX(int client_id, char* polymod, int polymodlen, char* coefmod, int coefmodlen, char* plainmod, int plainmodlen);
void AddInRow_SGX(char* buf, size_t len, int trainingSize, int precision);

sgx_status_t SGX_CDECL ocall_print(const char* str);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
