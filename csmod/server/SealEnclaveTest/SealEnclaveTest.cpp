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

using namespace std;
using namespace seal;

EncryptionParameters parms_sgx;
BigPoly secret_key_sgx;
BigPolyArray public_key;
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

void sigmod_sgx(char* buffer, size_t len,int trainingSize,int precision)
{	
	
	Encryptor encryptor(parms_sgx, public_key);
	Decryptor decryptor(parms_sgx, secret_key_sgx);
	BigPolyArray input;
	input.load(buffer);

	PolyCRTBuilder crtbuilder(parms_sgx);
	int slot_count = crtbuilder.get_slot_count();
	vector<BigUInt> values(slot_count, BigUInt(parms_sgx.plain_modulus().bit_count(), static_cast<uint64_t>(0)));

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

void DecreaseNoise_SGX(char* buf, size_t len)
{
	Encryptor encryptor(parms_sgx, public_key);
	Decryptor decryptor(parms_sgx, secret_key_sgx);

	Evaluator evaluator(parms_sgx);
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

void set_public_key(char* public_key_buffer, size_t len)
{
  public_key.load(public_key_buffer);
}

void set_secret_key(char* secret_key_buffer, size_t len)
{
  secret_key_sgx.load(secret_key_buffer);
}


void MakeConfigure_SGX(char* ConfigureBuffer, size_t len)
{
	memcpy(&parms_sgx, ConfigureBuffer, len);
}
