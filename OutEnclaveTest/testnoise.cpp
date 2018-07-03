#include "SealEnclaveTest_u.h"

#include "sgx_urts.h"
#include <stdio.h>
// #include <tchar.h> // windows environment
#include <string.h>
#include "Matrix.h"
#include <vector>
#include <algorithm>
#include <math.h>
#include <iostream>
#include <sstream>
#include <chrono>
#include <unordered_map>
#include "../Seal_OutEnclave/seal.h"
#include "TestData.h"
//#include "ReadData.h"
#include "MakeConfigure.h"

using namespace std;
using namespace seal;

//------------------------------------------------------------------------------
void ocall_print(const char* str) {
	printf("\033[96m%s\033[0m", str);
}

#define ENCLAVE_FILE "SealEnclaveTest.signed.so"
#define MAX_BUF_LEN 600000
#define round(x) (x - floor(x) >= 0.5 ? floor(x) + 1 : floor(x)) 
#define SIGNIFICANT_FIGURES 2
#define Simplify_NewSigmoid
#define DEBUG
#define SHOWRESULT

//vector<vector<double>> X;
//vector<double> Y;

EncryptionParameters  parms;
sgx_enclave_id_t      eid;
vector<BigPolyArray>  Hash_index;
vector<BigPolyArray>  Hash_result;
BigPolyArray          public_key;
#if defined (DEBUG) || defined(SHOWRESULT)
BigPoly               secret_key;
#endif // DEBUG
#ifdef SHOWRESULT
//vector<int>           idxVector;
vector<vector<int>>   orderOfRandomTraining;
vector<int>           trainV;
vector<int>           testV;
#endif



//--------------< Struct for the project >---------------------------------------------
static struct Configure
{
	// configure for Sigmoid function
	int Sigmoid_itor;
	double Sigmoid_y_inital;

	// configure for logistic regression
	double learningRate;
	int numEpochs;
	vector<double> maxItor;
	vector<double> psamples;

	//configure for HME parameters
	string p_poly_modulus;
	int p_coeff_modulus;
	int p_plain_modulus;
	vector<int> encoder_conf;

	int precision = 100;
} conf;

//---------< Round Function >----------------------------------------------------------
double Round(double value)
{
	int n = SIGNIFICANT_FIGURES;
	return round(value * pow(10, n)) / pow(10, n);
}

//---------< Create vector by step >--------------------------------------------------
void Create_Vector_By_Step(vector<double>& tmpVector, double start, double step, double end)
{
	for (double i = start; i <= end; i += step)
		tmpVector.push_back(i);
}

#if defined (DEBUG) || defined(SHOWRESULT)
//----------< Decrypt >------------------------------------------------------------------
double DecryptForDebug(BigPolyArray input)
{
	IntegerEncoder encoder(parms.plain_modulus());
	Decryptor decryptor(parms, secret_key);
	int ans = encoder.decode_int32(decryptor.decrypt(input));
	return ans;
}

//----------< Decode >------------------------------------------------------------------
BigPoly EncryptToEncode(BigPolyArray input)
{
	IntegerEncoder encoder(parms.plain_modulus());
	Decryptor decryptor(parms, secret_key);
	BigPoly ans = decryptor.decrypt(input);
	return ans;
}
#endif

//----------< Encoder >-----------------------------------------------------------------
BigPoly Encoder(int input)
{
	IntegerEncoder encoder(parms.plain_modulus());

	BigPoly encodeNumber = encoder.encode(input);
	return encodeNumber;
}

BigPoly FracEncoder(double input)
{
	//FractionalEncoder(const BigUInt &plain_modulus, const BigPoly &poly_modulus, int integer_coeff_count, int fraction_coeff_count, std::uint64_t base = 2);
	FractionalEncoder encoder(parms.plain_modulus(), parms.poly_modulus(),
		conf.encoder_conf[0], conf.encoder_conf[1], conf.encoder_conf[2]);

	BigPoly encodeNumber = encoder.encode(input);
	return encodeNumber;
}

//----------< Encryptor >---------------------------------------------------------------
BigPolyArray Encryption(int input)
{
	IntegerEncoder encoder(parms.plain_modulus());
	Encryptor encryptor(parms, public_key);

	BigPolyArray enc=encryptor.encrypt(encoder.encode(input));
	return enc;
}

//-------------------------< Decrease noise >----------------------------------------
BigPolyArray DecreaseNoise(BigPolyArray input)
{
	int buffer_length = 0;
	char *buffer = input.save(buffer_length);

	DecreaseNoise_SGX(eid, buffer, buffer_length);

	BigPolyArray return_ans;
	return_ans.load(buffer);

	return return_ans;
}

////---------------< DECRYPT FOR RECTIFIED LINEAR UNIT TRUNCATION >--------------
//BigPolyArray RectifiedLinUnitOp(BigPolyArray input, int features)
//{
//	int buffer_length = 0;
//	char *buffer = input.save(buffer_length);
//
//	AddInRow_SGX(eid, buffer, buffer_length,features);
//
//	BigPolyArray return_ans;
//	return_ans.load(buffer);
//
//	return return_ans;
//}

//---------------< Relinezation >---------------------------------
BigPolyArray Reline(BigPolyArray input)
{
	parms.decomposition_bit_count() = 10;

	KeyGenerator generator(parms);
	generator.generate();

	generator.generate_evaluation_keys(input.size() - 2);
	EvaluationKeys evaluation_keys = generator.evaluation_keys();
	Evaluator evaluator2(parms, evaluation_keys);

	input = evaluator2.relinearize(input);

	return input;
}

//----------< Random Function >----------------------------------------------------------
double GetRandom(double min, double max) {
	/* Returns a random double between min and max */
	return ((double)rand()*(max - min) / (double)RAND_MAX - min);
}

//----------< Hash Function >------------------------------------------------------------
BigPolyArray HashCiphertext(BigPolyArray input,int index)
{
	Evaluator evaluator(parms);
	BigPolyArray tmp1= evaluator.add(input, evaluator.negate(Hash_index[index]));
	BigPolyArray tmp2 = evaluator.add(input, evaluator.negate(Hash_index[index + 1]));
	BigPolyArray ans = evaluator.multiply(tmp1, tmp2);

	return ans;
}

//-------------< Addition in SGX >------------------------------------------------------
BigPolyArray AddInRow(BigPolyArray input,int trainingSize)
{
	int buffer_length = 0;
	char *buffer = input.save(buffer_length);

	AddInRow_SGX(eid, buffer, buffer_length, trainingSize,conf.precision);

	BigPolyArray return_ans;
	return_ans.load(buffer);

	delete[] buffer;

	return return_ans;
}

//-----------< New sigmoid function >---------------------------------------------------
#ifdef Simplify_NewSigmoid
BigPolyArray NewSigmoid(BigPolyArray input)
{
//	Evaluator evaluator(parms);
//	double y_inital = conf.Sigmoid_y_inital;
//	double y_after = 3*y_inital;
//
//	BigPolyArray ans;
//	ans = evaluator.multiply_plain(input, Encoder((int)y_after));
//
//#ifdef DEBUG
//	Decryptor decryptor(parms, secret_key);
//	PolyCRTBuilder crtbuilder(parms);
//	int slot_count = crtbuilder.get_slot_count();
//	vector<BigUInt> values(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(0)));
//
//	BigPoly test = decryptor.decrypt(ans);
//	crtbuilder.decompose(test, values);
//	for (size_t i = 0; i < 15; ++i)
//	{
//		cout << "(" << i << ", " << (values[i].to_dec_string()) << ")" << ((i != 14) ? ", " : "\n");
//	}
//#endif
//
//	ans = evaluator.add_plain(ans, Encoder(200));
//	return ans;

	return input;
}

#else
BigPolyArray NewSigmoid(BigPolyArray input)
{
	Evaluator evaluator(parms);

#ifdef DEBUG
	Decryptor decryptor(parms, secret_key);
#endif // DEBUG

	int itor = conf.Sigmoid_itor;
	double y_inital = conf.Sigmoid_y_inital;
	BigPolyArray ans;
	BigPoly y = Encoder(y_inital);
	BigPolyArray y0;
	BigPolyArray y_n;
	BigPolyArray y_tmp;
	BigPolyArray x_2;
	BigPolyArray x_half = evaluator.multiply_plain(input, Encoder(0.5));

	x_2 = evaluator.add_plain (evaluator.multiply(input, input), Encoder(1.0));
#ifdef DEBUG
	cout << "Noise in the x_2: " << decryptor.inherent_noise_bits(x_2)
		<< "/" << parms.inherent_noise_bits_max() << " bits" << endl;
#endif
	x_2 = DecreaseNoise(x_2);

	y_tmp = evaluator.multiply_plain(x_2, Encoder(y_inital*y_inital));

#ifdef DEBUG
	cout << "Noise in the y_tmp: " << decryptor.inherent_noise_bits(y_tmp)
		<< "/" << parms.inherent_noise_bits_max() << " bits" << endl;
#endif

	y_tmp = DecreaseNoise(y_tmp);
	y_tmp = evaluator.negate(y_tmp);
	y_n = evaluator.multiply_plain(evaluator.add_plain(y_tmp, Encoder(3.0)),y );
	y_n = evaluator.multiply_plain(y_n, Encoder(0.5));

#ifdef DEBUG
	cout << "Noise in the y_n: " << decryptor.inherent_noise_bits(y_n)
		<< "/" << parms.inherent_noise_bits_max() << " bits" << endl;
#endif

	y_n = DecreaseNoise(y_n);
	y0 = y_n;

	for (int i = 0; i < itor; i++)
	{
		y_tmp = evaluator.multiply(x_2, evaluator.multiply(y0, y0));
		y_tmp = DecreaseNoise(y_tmp);
		y_tmp = evaluator.negate(y_tmp);
		y_n = evaluator.multiply(y0, evaluator.add_plain(y_tmp, Encoder(3.0)));
		y_n = evaluator.multiply_plain(y_n, Encoder(0.5));
		y_n = DecreaseNoise(y_n);
		y0 = y_n;
	}

	ans = evaluator.add_plain(evaluator.multiply(x_half, y_n), Encoder(0.5));
	ans = DecreaseNoise(ans);
	return ans;
}
#endif

//-----------< sigmod function based on hash table >------------------------------------
BigPolyArray sigmod_Hash(BigPolyArray input)
{
	// This part is used to create a SGX buffer, and after we create buffer, we send this buffer to SGX.
	for (int i = 0; i < Hash_index.size()-1; i++)
	{
		BigPolyArray tmp_input;
		tmp_input = HashCiphertext(input,i);
		int buffer_length = 0;
		char *buffer = tmp_input.save(buffer_length);

		foo(eid, buffer, buffer_length);

		int secretIntValue = 0;
		int *secretIntPointer = &secretIntValue;
		check_Index(eid, secretIntPointer);
		if (secretIntValue)
		{
			cout << "return index " << i << endl;
			return Hash_result[i];
		}
		cout << ".";
	}
	cout << "return index " << Hash_result.size()-1 << endl;
	return Hash_result.back();
}

//-----------< sigmod function based on hme >-------------------------------------------
BigPolyArray sigmod_Hme(BigPolyArray input,int trainingSize)
{
	int buffer_length = 0;
	char *buffer = input.save(buffer_length);

	sigmod_sgx(eid, buffer, buffer_length, trainingSize,conf.precision);

	BigPolyArray return_ans;
	return_ans.load(buffer);

	return return_ans;
}

//-------------------------< Sigmoid Funciton >----------------------------------------------------
#ifdef Simplify_NewSigmoid
double SigmoidFunction(double input)
{
	return 0.75*input*conf.Sigmoid_y_inital + 0.5;
}
#else
double SigmoidFunction(double input)
{
	return 1 / (1 + exp(-input));
}
#endif
//----------------------< initialize some features >-----------------------------
void InitialHashTable()
{
	vector<double>hash_range;
	hash_range.push_back(-1000);
	Create_Vector_By_Step(hash_range, -5, 0.5, 5);
	hash_range.push_back(1000);
	for (int i = 0; i < hash_range.size(); i++)
	{
		Hash_index.push_back(Encryption(hash_range[i]));
		Hash_result.push_back(Encryption(SigmoidFunction(hash_range[i])));
	}
}


void InitialMaxtrix(vector<BigPolyArray>& XTrainWBC, BigPolyArray& yTrainWBC, vector<vector<double>>& plainTextData, vector<double>& plainTextY, int trainingSize, int precision)
{
	int idx = 0;
	for (int i = 0; i < trainingSize; i++)
	{
		idx = (int) GetRandom(0, X.size());
		bool unique = true;
		for (int j = 0; j < trainV.size(); j++) {
			if (idx == trainV[j]) {
				unique = false;
				break;
			}
		}
		if (unique) {
			trainV.push_back(i);
			//trainV.push_back(idx); //using this for random pick X
		}
		else {
			i--;
		}
	}

	Encryptor encryptor(parms, public_key);
	// Create the PolyCRTBuilder
	PolyCRTBuilder crtbuilder(parms);
	int slot_count = crtbuilder.get_slot_count();

	// Create a vector of values that are to be stored in the slots. We initialize all values to 0 at this point.
	vector<BigUInt> values(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(0)));

	// Create a vector for first column in X
	for (int i = 0; i < trainingSize; i++)
	{
		values[i] = 1;
	}
	BigPoly plain_composed_poly = crtbuilder.compose(values);
	BigPolyArray encrypted_composed_poly = encryptor.encrypt(plain_composed_poly);
	XTrainWBC[0] = encrypted_composed_poly;

	// Create CTX for other column in X
	for (int i = 0; i < X[0].size() ; i++)
	{
		for (int j = 0; j < trainV.size(); j++)
		{
			values[j] = X[trainV[j]][i];
			plainTextData[j][i+1] = X[trainV[j]][i];
		}
		plain_composed_poly = crtbuilder.compose(values);
		encrypted_composed_poly = encryptor.encrypt(plain_composed_poly);
		XTrainWBC[i + 1] = encrypted_composed_poly;
	}

	// Create CTX for Y
	for (int i = 0; i < trainV.size(); i++)
	{
		values[i] = Y[trainV[i]]*precision;
		plainTextY[i] = Y[trainV[i]];
	}
	plain_composed_poly = crtbuilder.compose(values);
	yTrainWBC = encryptor.encrypt(plain_composed_poly);

}

void InitialTestSet(vector<vector<double>>& XTest, vector<double>& yTest, int testSize, int trainingSize)
{
	int idx = 0;
	for (int i = 0; i < testSize; i++)
	{
		idx = (int)GetRandom(0, X.size());
		bool unique = true;
		for (int j = 0; j < testV.size(); j++) {
			if (idx == testV[j]) {
				unique = false;
				break;
			}
			else if (find(trainV.begin(), trainV.end(), idx) != trainV.end()) {		
				unique = false;
				break;
			}
		}
		if (unique) {
			testV.push_back(idx);
			//			XTrainWBC[i][0] = Encryption(1.0); // ADD '1' AS FIRST FEATURE VALUE FOR INTERCEPT TERM
			for (int k = 0; k < X[0].size(); k++) {
				XTest[i][k + 1] = X[idx][k];
			}
			yTest[i] = Y[idx];
			//cout << i + 1 << "Test sample " << i << " encrypted" << endl;
		}
		else {
			i--;
		}
	}
	
}

void InitialWeight(vector<double>& plaintextWeights, vector<BigPolyArray>& encryptedWeights, int feature, int trainingSize, int precision)
{
	// Create randomly initialized weights (plaintext) - then encrypt
	srand((unsigned)time(NULL));

	Encryptor encryptor(parms, public_key);
	// Create the PolyCRTBuilder
	PolyCRTBuilder crtbuilder(parms);
	int slot_count = crtbuilder.get_slot_count();
	vector<BigUInt> values(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(0)));

	// precision is the SCALING FACTOR (B)
	for (int i = 0; i < feature; i++)
	{
		plaintextWeights[i] = rand() / double(RAND_MAX);// using this for random pick weight
		//plaintextWeights[i] = 1;
		for (int j = 0; j < trainingSize; j++)
		{
			values[j] = plaintextWeights[i] * precision;
		}
		BigPoly plain_coeff_poly = crtbuilder.compose(values);
		encryptedWeights[i] = encryptor.encrypt(plain_coeff_poly);
	}
}

void InitialConfigure(MakeConfigure mconf)
{
	conf.Sigmoid_itor = mconf.ToInt(mconf.FindConfigure("Sigmoid_itor"));
	conf.Sigmoid_y_inital = mconf.ToDouble(mconf.FindConfigure("Sigmoid_y_inital"));
	conf.learningRate = mconf.ToDouble(mconf.FindConfigure("learningRate"));
	conf.numEpochs = mconf.ToInt(mconf.FindConfigure("runs"));
	conf.maxItor = mconf.ToDVector(mconf.FindConfigure("maxItor"));
	conf.psamples = mconf.ToDVector(mconf.FindConfigure("psamples"));
	conf.p_poly_modulus = mconf.FindConfigure("p_poly_modulus");
	conf.p_coeff_modulus = mconf.ToInt(mconf.FindConfigure("p_coeff_modulus"));
	conf.encoder_conf = mconf.ToIVector(mconf.FindConfigure("encoder_conf"));
	conf.p_plain_modulus = mconf.ToInt(mconf.FindConfigure("p_plain_modulus"));

	char* buffer = mconf.ReturnConf();
	MakeConfigure_SGX(eid, buffer, 500);

  cout<<"InitialConfigure finished."<<endl;
	//ReadData rd;
	//rd.readData(X,Y);
}

//-------------------------< Logistic Regression Weight >-------------------------------------------
void EncryptedLogisticRegression(
	vector<BigPolyArray>& XTrain, BigPolyArray& yTrain, vector<BigPolyArray>& w0, int maxEpochs,
	int numTrainingSamples, double learningRate,int nFeatures)
{
	Evaluator evaluator(parms);
	BigPoly encLearningRate = FracEncoder(learningRate);
//	cout << "learningRate: " << learningRate << endl;
//	cout << "Encoded learningRate: " << encLearningRate.to_string() << endl;
#ifdef DEBUG
	Decryptor decryptor(parms, secret_key);
#endif // DEBUG

	BigPolyArray inputToSigmoid1 = Encryption(0);
	BigPolyArray inputToSigmoid2 = Encryption(4);
	int i;
	for (i = 0; i < 1000; i++)
	{
		inputToSigmoid1 = evaluator.add(inputToSigmoid1, inputToSigmoid2);
    inputToSigmoid1 = evaluator.multiply(inputToSigmoid1, inputToSigmoid2);
    inputToSigmoid1 = evaluator.multiply(inputToSigmoid1, inputToSigmoid2);
    inputToSigmoid1 = evaluator.multiply(inputToSigmoid1, inputToSigmoid2);
    inputToSigmoid1 = evaluator.multiply(inputToSigmoid1, inputToSigmoid2);
//    inputToSigmoid1 = evaluator.add(inputToSigmoid1, inputToSigmoid2);
//    inputToSigmoid1 = evaluator.add(inputToSigmoid1, inputToSigmoid2);
//    inputToSigmoid1 = evaluator.add(inputToSigmoid1, inputToSigmoid2);
//		inputToSigmoid2 = evaluator.multiply(inputToSigmoid1, inputToSigmoid2);

#ifdef DEBUG
		PolyCRTBuilder crtbuilder(parms);
		int slot_count = crtbuilder.get_slot_count();
		vector<BigUInt> values(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(0)));

		BigPoly ans = decryptor.decrypt(inputToSigmoid1);

		crtbuilder.decompose(ans, values);
		cout << "The decrypted input to sigmoid: " << endl;
		for (size_t i = 0; i < numTrainingSamples; ++i)
		{
			cout << "(" << i << ", " << (values[i].to_dec_string()) << ")" << ((i != numTrainingSamples - 1) ? ", " : "\n");
		}
		cout << "Noise in the inputToSigmoid: " << decryptor.inherent_noise_bits(inputToSigmoid1)
			<< "/" << parms.inherent_noise_bits_max() << " bits" << endl;
#endif
    inputToSigmoid1 = DecreaseNoise(inputToSigmoid1);
    
#ifdef DEBUG
		PolyCRTBuilder crtbuilder2(parms);
		int slot_count2 = crtbuilder2.get_slot_count();
		vector<BigUInt> values2(slot_count2, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(0)));

		BigPoly ans2 = decryptor.decrypt(inputToSigmoid1);

		cout << "(################# After DecreaseNoise)Noise in the inputToSigmoid: " << decryptor.inherent_noise_bits(inputToSigmoid1)
			<< "/" << parms.inherent_noise_bits_max() << " bits" << endl;
#endif
	}
}

//-----------------------------< Get Final probability > ------------------------------
#if defined (SHOWRESULT)|| defined(DEBUG)
vector<double> Predict(const vector<vector<double>>& XTest, const vector<double>& YTest, 
	const vector<BigPolyArray>& w0, int numFeatures, int testSize, int precision)
{
	/*char skb[MAX_BUF_LEN];*/
	// INITIALIZE ON HEAP 
	char * skb = new char[MAX_BUF_LEN]; 
 // cout<<"data allocated"<<endl;
	get_secret_key(eid, skb, MAX_BUF_LEN);
 // cout<<"secret key allocated"<<endl;
	secret_key.load(skb);
 
//  cout<<"skb initialized"<<endl;

//	EncryptionParameters parms; // use the global one
//  cout<<"parms allocated"<<endl;
	PolyCRTBuilder crtbuilder(parms);
//  cout<<"parameters built"<<endl;
  
	int slot_count = crtbuilder.get_slot_count();
//  cout<<"get_slot_count finished."<<endl;
	vector<BigUInt> values(slot_count, BigUInt(parms.plain_modulus().bit_count(), static_cast<uint64_t>(0)));
//  cout<<"values finished."<<endl;
  
	vector<double> weight;
	for (int i = 0; i < w0.size(); i++)
	{
		BigPoly ans = EncryptToEncode(w0[i]);
//    cout<<"Number "<<i<<": "<<ans.to_string()<<endl;
		crtbuilder.decompose(ans, values);


		double decryptedWeight = (values[0].to_double())/precision;
		weight.push_back(decryptedWeight);
	}

	vector<double> predictions;
	for (int i = 0; i < testSize; i++)
	{
		double inputToSigmoid = 0;
		for (int j = 0; j < numFeatures + 1; j++)
		{
			inputToSigmoid = XTest[i][j] * weight[j] + inputToSigmoid;
		}
		inputToSigmoid = SigmoidFunction(inputToSigmoid);
		cout << "sigmoid output prior to ReLU: " << inputToSigmoid << endl;
		if (inputToSigmoid > 1) {
			inputToSigmoid = 1;
		}
		else if (inputToSigmoid < 0) {
			inputToSigmoid = 0;
		}
		//cout  << tmpmulti << endl;
		predictions.push_back(inputToSigmoid);
	}

	cout << "Predictions!!!" << endl;
	for (int i = 0; i < predictions.size(); i++) {
		cout << "The prediction for the " << i+1 << "th example = " << predictions[i] << " actual Y = " << YTest[i] << endl;
	}
	delete skb;
	return predictions;
}

//--------------------------------< Get AUC >------------------------------------------
double AUC(vector<double> predicted, vector<double>& yTest)
{
	int nTarget=0;
	int nBackground=0;

	for (int i = 0; i < yTest.size(); i++)
	{
		if (yTest[i] == 1)
			nTarget++;
		if (yTest[i] == 0)
			nBackground++;
	}

	vector<double> _p;
	_p = predicted;
	_p.push_back(10);
	sort(_p.begin(), _p.end());

	vector<vector<double>> map(_p.size(), vector<double>(2,0));
	for (int i = 0; i < _p.size(); i++)
		map[i][0] = _p[i];

	double count = 1;
	double sum = 0;
	for (int i = 0; i < map.size()-1; i++)
	{
		if (map[i][0] != map[i + 1][0])
		{
			sum = 0;
			for (int j = i; j >=i-count+1; j--)
				sum += j+1;
			for (int j = i; j >= i - count + 1; j--)
				map[j][1] = sum / count;
			count = 1;
		}
		else
			count++;
	}

	double rSum = 0;
	for (int i = 0; i < predicted.size(); i++)
	{
		if (yTest[i] == 1)
		{
			for (int j = 0; j < map.size() - 1; j++)
			{
				if (map[j][0] == predicted[i])
				{
					rSum += map[j][1];
					break;
				}
			}
		}
	}
		
	double AUC = 0.0;
	AUC = (rSum - (nTarget*nTarget + nTarget) / 2) / (nTarget*nBackground);
	cout << "AUC: " << AUC << endl;
	return AUC;

}

//---------------------------< Show the accuracy result >------------------------------
vector<double> PlaintextLRTest(vector<double> _w0, double learningRate, int trainingSize, int testSize, 
	int numFeatures, vector<vector<double>> XTest, vector<double> YTest)
{
	//vector<vector<double>> _X(trainingSize,vector<double>(X[0].size()+1,1.0));
	//for (int i = 0; i < trainingSize; i++)
	//	for (int j = 1; j < X[0].size()+1; j++)
	//		_X[i][j]=X[trainV[i]][j-1];

	// LOOP THROUGH ALL DATA *maxEpochs* NUMBER OF TIMES
	for (int epoch = 0; epoch < orderOfRandomTraining.size(); epoch++) {

		for (int i = 0; i < trainingSize; i++)
		{
			vector<double> _tw(_w0.size(), 0.0);
			double inputToSigmoid = 0;
			//		cout << "Plaintext: value of XTrain, weight and inputToSigmoid:" << endl;
			for (int j = 0; j < _tw.size(); j++)
			{
				inputToSigmoid = XTest[orderOfRandomTraining[epoch][i]] [j] * _w0[j] + inputToSigmoid;
				cout << XTest[orderOfRandomTraining[epoch][i]][j] << "    " << _w0[j] << "    " << inputToSigmoid << endl;
			}
			//cout << "Plaintext: value of sigmoid(inputToSigmoid):" << endl;
			for (int k = 0; k < _w0.size(); k++)
			{
				double error = 0;
				double gradient = 0;
				double weightUpdateVal = 0;

				double y_inital = conf.Sigmoid_y_inital;
				double y_after = 0.75*y_inital;
				double output = inputToSigmoid*y_after + 0.5;
				//			cout << "Plaintext output: " << output << endl;
				error = output - YTest[orderOfRandomTraining[epoch][i]];
				cout << "Error on plaintext data for epoch " << epoch << " : " << error << endl;
				gradient = error * XTest[orderOfRandomTraining[epoch][i]][k];
				weightUpdateVal = learningRate * gradient;
				_tw[k] = weightUpdateVal;
			}
			for (int i = 0; i < _w0.size(); i++)
				_w0[i] = _w0[i] - _tw[i];
		}
	}

	//int nSamples = XTest.row;
	//Matrix<double> _XT(nSamples, 1 + XTest.col);
	//_XT.Set_Default_Value(1.0);
	//for (int i = 0; i < _XT.row; i++) {
	//	for (int j = 1; j < _XT.col; j++)
	//		_XT.assign(i, j, XTest.at(i, j - 1));
	//}

	// PREDICTION STEP
	vector<double> _probability;
	//cout << " The input of sigmoid is: " << endl;
	for (int i = 0; i < testSize; i++)
	{
		double inputToSigmoid = 0;
		for (int j = 0; j < 1 + numFeatures; j++)
		{
			inputToSigmoid = XTest[i][j] * _w0[j] + inputToSigmoid;
		}
		//cout  << tmpmulti << endl;
		_probability.push_back(SigmoidFunction(inputToSigmoid));
	}
//	cout << endl;
	//cout << "The resulting weights on plaintext data: " << endl;
	//for (int i = 0; i < _w0.row; i++)
	//	cout << _w0.at(i, 0) << endl;
	//cout << endl;

	AUC(_probability, YTest);

	return _w0;
}
#endif

//----------------------------< Main Test Stub >---------------------------------------
#define TEST_LOGISTIC_REGRESSION
#ifdef TEST_LOGISTIC_REGRESSION
int main()
{
	// Create sgx enclave
	sgx_status_t        ret = SGX_SUCCESS;
	sgx_launch_token_t  token = { 0 };
	int updated = 0;
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
	if (ret != SGX_SUCCESS)
		return -1;

	// Initizal the Configure
	MakeConfigure mconf;
	mconf.Initalize();
	InitialConfigure(mconf);

	// Create encryption parameters
  //cout<<"***************    p_poly_modulus: "<<conf.p_poly_modulus<<"endchar"<<endl;
	parms.poly_modulus() = conf.p_poly_modulus;
 // cout<<"***************    default_parameter_options"<<endl;
	parms.coeff_modulus() = ChooserEvaluator::default_parameter_options().at(conf.p_coeff_modulus);
  //cout<<"***************    p_plain_modulus"<<endl;
	parms.plain_modulus() = conf.p_plain_modulus;
  

	// Generate keys.
	cout << "... Generating keys ..." << endl;
	generate_key_sgx(eid);
	/*char public_key_buffer[MAX_BUF_LEN];*/
	char * public_key_buffer = new char[MAX_BUF_LEN];
	get_public_key(eid, public_key_buffer, MAX_BUF_LEN);
	public_key.load(public_key_buffer);
	cout << "... Public key generation complete ..." << endl;


#ifdef DEBUG
	//-------------< test for some function and feature >-------------------------------------------------
	cout << "This is a test for sigmoid function and sgx" << endl;
	char * secret_key_buffer = new char[MAX_BUF_LEN];
	get_secret_key(eid, secret_key_buffer, MAX_BUF_LEN);
	secret_key.load(secret_key_buffer);
	cout << "... secret key generation complete" << endl;
#endif

	int precision = conf.precision;
	// WANT TO USE THIS FOR TESTING ON **REAL** DATA: Set random matrix for training
	int trainingSize = 4;
	int numFeatures = X[0].size();
	vector<BigPolyArray> XTrainWBC(trainingSize+1);
	BigPolyArray yTrainWBC;
	vector<vector<double>> trainingDataForTesting(trainingSize, vector<double>(numFeatures + 1, 0.0));
	vector<double> trainingYForTesting(trainingSize, 1);
	InitialMaxtrix(XTrainWBC, yTrainWBC, trainingDataForTesting, trainingYForTesting, trainingSize,precision);
	//Set random Matrix for Testing
	int testSize = 0;
	vector<vector<double>> xTest(testSize, vector<double>(numFeatures + 1, 1));
	vector<double> yTest(testSize, 0);
	InitialTestSet(xTest, yTest, testSize, trainingSize);
//	cout << " Complete Matrix" << endl;


	// Give random value for weight.
	vector<double> plainWeights(numFeatures + 1, 1);
	vector<BigPolyArray> encryptWeights(numFeatures+1);
	InitialWeight(plainWeights, encryptWeights, numFeatures + 1, trainingSize,precision);
	
	// Set parameter value of Logistic Regression
	double learnRate = conf.learningRate;
	int numEpochs = conf.numEpochs;

	// Start the logistic Regression		
	// PERFORM LOGISTIC REGRESSION ON ENCRYPTED AND PLAINTEXT DATA
	cout << " Start logistic regression" << endl;

	cout << endl;
	cout << "**********************************************************************************************" << endl;
	cout << "Beginning encrypted Logistic Regression test:" << endl;
	EncryptedLogisticRegression(XTrainWBC, yTrainWBC, encryptWeights, numEpochs, trainingSize, learnRate,numFeatures+1);

	cout << endl;
	cout << "**********************************************************************************************" << endl;

	cout << "... All is completed ..." << endl;

	// Destroy the Enclave
	if (SGX_SUCCESS != sgx_destroy_enclave(eid))
		cout << "destroy error" << endl;
	cout << "... Destroy the enclave successfully ..." << endl;

	// deallocate memory on the heap!
	delete public_key_buffer;
	delete secret_key_buffer;
  return 0;
}

#endif

