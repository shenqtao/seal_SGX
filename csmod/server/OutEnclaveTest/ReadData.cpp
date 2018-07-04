#include "ReadData.h"

const int ENTRY_LENGTH = 24;

void ReadData::readData(vector<vector<double>>& X, vector<double>& Y)
{
	ifstream infile("data.txt");
	string line;
	while (getline(infile, line))
	{
		_rX.clear();
		int endEntry = 0;
		int length = 0;
		// cout << "Printing length of a line: " << line.length() << endl;
		for (int i = 0; i < line.length(); i++)
		{
			if (i == line.length() - ENTRY_LENGTH)
			{
				if (line[i] == '0')
					Y.push_back(0.0);
				else
					Y.push_back(1.0);
				break;
			}
			// SET TARGET: DETERMINE IF THE VALUE OF LAST ENTRY IN THE ROW IS '0' OR '1'
			else if (line[i] == '0')
			{
				_rX.push_back(0.0);
				while (line[i] != ',') {
					i++;
				}
				endEntry = i + 1;

			} // NOT AT A ZERO-VALUED ENTRY OR TARGET VALUE
			else
			{
				while (line[i] != '-' && line[i] != '+') {
					i++;
				}
				string num = line.substr(endEntry, i - endEntry);
				string point = line.substr(i + 1, 2);
				string::size_type sz;

				double dVal = stod(num,&sz);
				int power = stoi(point,&sz);

				int j = 0;
				if (line[i] == '-') {
					for (; j < power; j++) {
						dVal = dVal / 10;
					}
					_rX.push_back(dVal);
				}
				else {
					for (; j < power; j++) {
						dVal = dVal * 10;
					}
					_rX.push_back(dVal);
					
				}

				while (line[i] != ',') {
					i++;
				}
				endEntry = i + 1;
			}
		}
		X.push_back(_rX);
	}
}
