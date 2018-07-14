#include "SealEnclaveTest_t.h"

#include "sgx_trts.h"

#include <sstream>
//#include <cstring>
#include <chrono>
#include <vector>
#include "../SEAL/seal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <cmath>
#include <map>

using namespace std;
using namespace seal;

//------------------------------------------------------------------------------
/*
* printf:
*   Invokes OCALL to display the enclave buffer to the terminal.
*/
//------------------------------------------------------------------------------
void printf(const char *fmt, ...) {
	char buf[BUFSIZ] = { '\0' };
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);
	ocall_print(buf);
}

map<int, EncryptionParameters> parms_sgx;
//EncryptionParameters parms_sgx;
map<int, BigPoly> secret_key_sgx;
//BigPoly secret_key_sgx;
map<int, BigPolyArray> public_key;
//BigPolyArray public_key;



double decrypted_number;

int check_Index()
{
	int flag = 0;
	if (decrypted_number > 0)
		flag = 0;
	else
		flag = 1;
	return flag;
}

void sigmod_sgx(int client_id, char* buffer, size_t len,int trainingSize,int precision)
{	
	
	Encryptor encryptor(parms_sgx[client_id], public_key[client_id]);
	Decryptor decryptor(parms_sgx[client_id], secret_key_sgx[client_id]);
	BigPolyArray input;
	input.load(buffer);

	PolyCRTBuilder crtbuilder(parms_sgx[client_id]);
	int slot_count = crtbuilder.get_slot_count();
	vector<BigUInt> values(slot_count, BigUInt(parms_sgx[client_id].plain_modulus().bit_count(), static_cast<uint64_t>(0)));

	BigPoly ans = decryptor.decrypt(input);
	crtbuilder.decompose(ans, values);

	// MULTIPLYING THE SIGMOID OUTPUT BY THE LEARNING RATE (MULTIPLYING Y_TRUE*LEARNING_RATE BEFORE ENCRYPTION)
	double learning_rate = 0.01;
	for (int i = 0; i < trainingSize; i++)
	{
		double result = values[i].to_double() / precision;
		result = 1 / (1 + exp(-result));
		values[i] = (int) (result * learning_rate * precision);
	}

	BigPoly plain_coeff_poly = crtbuilder.compose(values);
	BigPolyArray output = encryptor.encrypt(plain_coeff_poly);
	
	int length = 0;
	char* tmp_buf = output.save(length);

	memcpy(buffer,tmp_buf,length);
	delete[] tmp_buf;
}

void DecreaseNoise_SGX(int client_id, char* buf, size_t len)
{
  // test whether the public/private keys have been set
  // if yes, retrieve the keys; otherwise, print error message
  
	Encryptor encryptor(parms_sgx[client_id], public_key[client_id]);
	Decryptor decryptor(parms_sgx[client_id], secret_key_sgx[client_id]);

//	Evaluator evaluator(parms_sgx);
	BigPoly encoded_number;
	BigPolyArray encrypted_rational;
	BigPoly plain_result;

	encrypted_rational.load(buf);
	plain_result = decryptor.decrypt(encrypted_rational);
 
  // ww31: it may need to decode & encode, however I remove it for now
	encrypted_rational = encryptor.encrypt(plain_result);

	int length = 0;
	char* tmp_buf = encrypted_rational.save(length);

	memcpy(buf, tmp_buf, length);

	delete[] tmp_buf;

}

// ********************** CHECK WITH YONGSOO ON EVALUATING THE ~0,1 VALS WITHIN plainModBound space *****************
void AddInRow_SGX(char* buf, size_t len,int trainingSize,int precision)
{
}

void set_public_key(int client_id, char* public_key_buffer, size_t len)
{
  public_key[client_id].load(public_key_buffer);
}

void set_secret_key(int client_id, char* secret_key_buffer, size_t len)
{
  secret_key_sgx[client_id].load(secret_key_buffer);
}


void MakeConfigure_SGX(int client_id, char* polymod, int polymodlen, char* coefmod, int coefmodlen, char* plainmod, int plainmodlen)
{
  polymod[polymodlen] = 0;
  coefmod[coefmodlen] = 0;
  plainmod[plainmodlen] = 0;
  printf("................. client id: %d, polymod: %s, length: %d\n", client_id, polymod, polymodlen);
  
  parms_sgx[client_id].poly_modulus() = polymod;
  parms_sgx[client_id].coeff_modulus() = coefmod;
  parms_sgx[client_id].plain_modulus() = atoi(plainmod);
  
//	memcpy(&parms_sgx, ConfigureBuffer, len);
//  printf("sizeof(EncryptionParameters): %d, len: %d\n", sizeof(EncryptionParameters), len);
  printf("parms_sgx.coeff_modulus_: %s\n", coefmod);
  printf("parms_sgx.plain_modulus_: %d\n", atoi(plainmod));
}
