#pragma once
#include <stdio.h>
#include <string>
#include <vector>
#include <iostream>

using namespace std;

class MakeConfigure
{
public:
	void Initalize();
	string FindConfigure(string input);
	int ToInt(string input);
	char* ReturnConf() { return ConfigureBuffer; }
	double ToDouble(string input);
	vector<double> ToDVector(string input);
	vector<int> ToIVector(string input);
private:
	char ConfigureBuffer[500];

};    