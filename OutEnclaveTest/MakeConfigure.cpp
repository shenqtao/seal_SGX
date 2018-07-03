#include "MakeConfigure.h"
#include <iostream>
#include <fstream>


void MakeConfigure::Initalize()
{
	cout << "... Read the configure file ..." << endl;

	char buffer[256];
	fstream outFile;
	outFile.open("Configure.txt", ios::in);
	int count = 0;
	while (!outFile.eof())
	{
		outFile.getline(buffer, 256, '\n');
		for (int i = 0; i < 256; i++)
		{
			if (buffer[i] == '\0')
			{
				ConfigureBuffer[count] = '#';
				count++;
				break;
			}
			else
				ConfigureBuffer[count] = buffer[i];
			count++;
		}
	}
	outFile.close();

	cout << "... Finish reading configure file ..." << endl;
}

string MakeConfigure::FindConfigure(string input)
{
	string ans;
	string tCon = ConfigureBuffer;
	string temp;

	for (int i = 0; i < 500; i++)
	{
		if (ConfigureBuffer[i] == input[0])
		{
			temp=tCon.substr(i, input.length());
			if (temp == input)
			{
				int count = 1;
				i += input.length();
				while (ConfigureBuffer[i] != '=')
					i++;
				while (ConfigureBuffer[i+count] != '#')
					count++;
				ans = tCon.substr(i + 1, count-1);
				break;
			}
		}
		else
		{
			while (ConfigureBuffer[i] != '#')
				i++;
		}
	}

	return ans;
}

int MakeConfigure::ToInt(string input)
{
	int value = atoi(input.c_str());
	return value;
}

double MakeConfigure::ToDouble(string input)
{
	string::size_type sz;
	double ans = stod(input, &sz);
	return ans;
}

vector<double> MakeConfigure::ToDVector(string input)
{
	vector<double> ans;
	int position = 0;
	for (int i = 0; i < input.length(); i++)
	{
		if (input[i] == ';')
		{
			string temp = input.substr(position, i - position);
			ans.push_back(ToDouble(temp));
			position = i + 1;
		}
		if (i == input.length() - 1)
		{
			string temp = input.substr(position, i - position+1);
			ans.push_back(ToDouble(temp));
		}
	}
	return ans;
}

vector<int> MakeConfigure::ToIVector(string input)
{
	vector<int> ans;
	int position = 0;
	for (int i = 0; i < input.length(); i++)
	{
		if (input[i] == ';')
		{
			string temp = input.substr(position, i - position);
			ans.push_back(ToInt(temp));
			position = i + 1;
		}
		if (i == input.length() - 1)
		{
			string temp = input.substr(position, i - position + 1);
			ans.push_back(ToInt(temp));
		}
	}
	return ans;
}
