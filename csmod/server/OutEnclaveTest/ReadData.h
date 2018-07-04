#include <vector>
#include <iostream>
#include <string>
#include <sstream>
#include <fstream>
//#include "TestData.h"

using namespace std;
//vector<vector<double>> X;
//vector<double> Y;


class ReadData
{
public:
	void readData(vector<vector<double>>& X,vector<double>& Y);
private:
	vector<double> _rX;
};
