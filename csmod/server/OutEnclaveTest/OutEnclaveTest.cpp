#include "SealEnclaveTest_u.h"
#include "../socket_server.h"
#include "sgx_urts.h"
#include <stdio.h>
#include <string.h>
#include "Matrix.h"
#include <vector>
#include <algorithm>
#include <math.h>
#include <iostream>
#include <sstream>
#include <chrono>
#include <unordered_map>
#include <assert.h>
#include "TestData.h"
#include "MakeConfigure.h"

using namespace std;

#define ENCLAVE_FILE "SealEnclaveTest.signed.so"
#define MAX_BUF_LEN 600000
#define round(x) (x - floor(x) >= 0.5 ? floor(x) + 1 : floor(x)) 
#define SIGNIFICANT_FIGURES 2
#define Simplify_NewSigmoid
#define DEBUG
#define SHOWRESULT

//vector<vector<double>> X;
//vector<double> Y;

//EncryptionParameters  parms;
sgx_enclave_id_t      eid;

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

//-------------------------< Decrease noise >----------------------------------------
/*BigPolyArray DecreaseNoise(BigPolyArray input)
{
	int buffer_length = 0;
	char *buffer = input.save(buffer_length);
  printf("!!!!!!!!!!!!!!!!1buffer length: %d\n", buffer_length);
	DecreaseNoise_SGX(eid, buffer, buffer_length);

	BigPolyArray return_ans;
	return_ans.load(buffer);

	return return_ans;
}*/

//----------< Random Function >----------------------------------------------------------
double GetRandom(double min, double max) {
	/* Returns a random double between min and max */
	return ((double)rand()*(max - min) / (double)RAND_MAX - min);
}


//-------------< Addition in SGX >------------------------------------------------------
/*BigPolyArray AddInRow(BigPolyArray input,int trainingSize)
{
	int buffer_length = 0;
	char *buffer = input.save(buffer_length);

	AddInRow_SGX(eid, buffer, buffer_length, trainingSize,conf.precision);

	BigPolyArray return_ans;
	return_ans.load(buffer);

	delete[] buffer;

	return return_ans;
}*/

//-----------< sigmod function based on hme >-------------------------------------------
/*BigPolyArray sigmod_Hme(BigPolyArray input,int trainingSize)
{
	int buffer_length = 0;
	char *buffer = input.save(buffer_length);

	sigmod_sgx(eid, buffer, buffer_length, trainingSize,conf.precision);

	BigPolyArray return_ans;
	return_ans.load(buffer);

	return return_ans;
}*/

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


int main()
{
  // Create sgx enclave
  sgx_status_t        ret = SGX_SUCCESS;
  sgx_launch_token_t  token = { 0 };
  int updated = 0;
  ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
  if (ret != SGX_SUCCESS)
  	return -1;
  cout<<"Enclave loaded."<<endl;
  // Initizal the Configure
  MakeConfigure mconf;
  mconf.Initalize();
  InitialConfigure(mconf);
  
  //	parms.poly_modulus() = conf.p_poly_modulus;
  //	parms.coeff_modulus() = ChooserEvaluator::default_parameter_options().at(conf.p_coeff_modulus);
  //	parms.plain_modulus() = conf.p_plain_modulus;
  int listen_fd = socket_bind(IPADDRESS, PORT);
  int max_fd = -1;
  int nready;
  fd_set readfds;
  int clients_fd[IPC_MAX_CONN];
  
  memset(clients_fd, -1, sizeof(clients_fd));
  
  while (true) {
  
      FD_ZERO(&readfds);
      FD_SET(listen_fd, &readfds);
      max_fd = listen_fd;
  
      for (size_t i=0; i < IPC_MAX_CONN; i++)
      {
          if (clients_fd[i] != -1) {
              FD_SET(clients_fd[i], &readfds);
              max_fd = clients_fd[i] > max_fd ? clients_fd[i] : max_fd;
          }
      }
      nready = select(max_fd+1, &readfds, NULL, NULL, NULL);
      if (nready == -1) {
          perror("select error.");
          return 1;
      }
      if (FD_ISSET(listen_fd, &readfds)) {
          accpet_client(clients_fd, listen_fd);
      }
      recv_client_msg(clients_fd, &readfds);
  }
  
  // Destroy the Enclave
  if (SGX_SUCCESS != sgx_destroy_enclave(eid))
  	cout << "destroy error" << endl;
  cout << "... Destroy the enclave successfully ..." << endl;
  
  
  return 0;
}

// message processing
/**
 * 通过select查询到fdset之后,循环遍历每个fd是否就绪
 * @param clients_fd
 * @param readfds
 */
void recv_client_msg(int *clients_fd, fd_set *readfds) {
    char *buf = new char[bufflen];
    struct message_head head;
    for (size_t i = 0; i < IPC_MAX_CONN; ++i) {
        if (clients_fd[i] == -1) {
            continue;
        } else if (FD_ISSET(clients_fd[i], readfds)) {
//            int n = read(clients_fd[i], buf, 1024);
            int n = read(clients_fd[i], &head, sizeof(struct message_head));
            if (n <= 0) {
                FD_CLR(clients_fd[i], readfds);
                printf("one socket close\n");
                close(clients_fd[i]);
                clients_fd[i] = -1;
                continue;
            }
            printf("command is: %d, buffer length: %d\n", head.cmd, head.data_len);
            read(clients_fd[i], buf, head.data_len);
            if(head.cmd == ENC_PARAMETER)
            {
              MakeConfigure_SGX(eid, buf, head.data_len);
            }
            
            sleep(3);
            char *ret = "processed";
            write(clients_fd[i], ret, strlen(ret));
            //handle_client_msg(clients_fd[i], &head, buf);
        }
    }
    delete [] buf;
}

/**
 * 在这里处理SGX业务
 * @param fd
 * @param buf
 */
void handle_client_msg(int fd, struct message_head *head, char *buf) {

    switch (head->cmd) {
        case ENC_PARAMETER:
            break;
        case PRIVATE_KEY:
            break;
        case ENCRYPT_DATA:
            break;
        case DECRYPT_DATA:
            break;
        default:
            break;
    }

    int len, i;
    assert(buf);
    printf("recv buf is:%s\n", buf);
    len = strlen(buf);
    for (i=0; i<len; i++) {
        if (buf[i] >= 'a' && buf[i] <= 'z') {
            buf[i] += 'A'- 'a';
        }
    }
    write(fd, buf, strlen(buf));

}