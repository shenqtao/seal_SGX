#ifndef SEALENCLAVETEST_U_H__
#define SEALENCLAVETEST_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));

sgx_status_t foo(sgx_enclave_id_t eid, char* buf, size_t len);
sgx_status_t generate_key_sgx(sgx_enclave_id_t eid);
sgx_status_t get_public_key(sgx_enclave_id_t eid, char* public_key_buffer, size_t len);
sgx_status_t get_secret_key(sgx_enclave_id_t eid, char* secret_key_buffer, size_t len);
sgx_status_t sigmod_sgx(sgx_enclave_id_t eid, char* buffer, size_t len, int trainingSize, int precision);
sgx_status_t check_Index(sgx_enclave_id_t eid, int* retval);
sgx_status_t DecreaseNoise_SGX(sgx_enclave_id_t eid, char* buf, size_t len);
sgx_status_t MakeConfigure_SGX(sgx_enclave_id_t eid, char* ConfigureBuffer, size_t len);
sgx_status_t AddInRow_SGX(sgx_enclave_id_t eid, char* buf, size_t len, int trainingSize, int precision);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
