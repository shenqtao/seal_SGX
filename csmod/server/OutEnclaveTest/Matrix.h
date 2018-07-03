#pragma once

#include<iostream>
#include<math.h>
using namespace std;

int Pow(int x, int y) {
	int ans, b, i;
	if (y == 0)return 1;
	if (y < 0) return -1;
	for (i = y, b = 0; i > 0; i >>= 1) b++;
	for (ans = 1, i = b - 1; i >= 0; i--) {
		if (y & (1 << i)) {
			ans = ans * ans * x;
		}
		else {
			ans = ans * ans;
		}
	}
	return ans;
}

template <typename T>
class Matrix {
	//class Matrix by felix021
	//usage: Matrix<typename> varname(row, col[, mod]);
	//如果typename不是short/int/long/long long
	//那么取模运算需要包含math.h头文件(使用fmod函数)
	//取模运算的代码仅在 + - * 三个函数内. 

public:
	T **data;
	Matrix *temp;
	int row, col, modnum;
	//无参构造函数，没有给定矩阵的大小时，输出错误提示
	Matrix() {
		printf("Size parameter invalid!\n");
	}
	//构造函数， r是行数，c是列数，若给定m>0, 则在求和/差/积时对m取模
	Matrix(int r, int c, int m = 0) {
		int i;
		temp = NULL;
		row = r, col = c;
		data = new T *[r]; //分配一个 T *[r]类型的数组给data
		for (i = 0; i < r; i++) {
			data[i] = new T[c];  //给data下的每个指针分配内存, 类型为 T [c]
		}
		if (m > 0) modnum = m;
		else modnum = 0;
	}
	//析构函数，用于释放分配的内存
	//~Matrix() {
	//	int i;
	//	if (temp != NULL) { delete temp; }
	//	for (i = 0; i < row; i++) delete data[i];
	//	delete data;
	//}
	//赋值，给第i行第j列的元素赋值为 a
	void assign(int i, int j, const T a) {
		if (i < 0 || i >= row || j < 0 || j >= col) {
			printf("Invalid row/column number.\n");
			return;
		}
		else {
			data[i][j] = a;
		}
	}
	// set default value for a metrix
	void Set_Default_Value(const T a){
		for (int i = 0; i < row; i++)
			for (int j = 0; j < col; j++)
				data[i][j] = a;
	}
	void Set_Default_Random_Value(int range)
	{
		if(range==1)
			for (int i = 0; i < row; i++)
				for (int j = 0; j < col; j++)
					data[i][j] = rand() / (double)(RAND_MAX);
		else
			for (int i = 0; i < row; i++)
				for (int j = 0; j < col; j++)
					data[i][j] = rand()%range;
	}
	//取出元素，给第i行第j列的元素的值
	T at(int i, int j) {
		if (i < 0 || i >= row || j < 0 || j >= col) {
			printf("Invalid row/column number.\n");
			return data[0][0];
		}
		else {
			return data[i][j];
		}
	}
	//重载<<运算符，可用cout输出
	friend inline ostream & operator<<(ostream &os, const Matrix &a) {
		int i, j;
		for (i = 0; i < a.row; i++) {
			for (j = 0; j < a.col - 1; j++) {
				os << a.data[i][j] << " ";
			}
			os << a.data[i][j];
			os << endl;
		}
		return os;
	}
	//重载>>运算符，可用cin输入
	friend inline istream & operator >> (istream &is, const Matrix &a) {
		int i, j;
		for (i = 0; i < a.row; i++) {
			for (j = 0; j < a.col; j++) {
				is >> a.data[i][j];
			}
		}
		return is;
	}
	//重载=运算符，要求两个矩阵的大小相同
	Matrix & operator = (const Matrix &a) {
		int i, j;
		if (row != a.row || col != a.col) {
			printf("Unmatch Matrix!\n");
			return *this;
		}
		for (i = 0; i < row; i++) {
			for (j = 0; j < col; j++) {
				data[i][j] = a.data[i][j];
				//if (modnum > 0) {
				//	data[i][j] = mod(data[i][j]);
				//}
			}
		}
		return *this;
	}
	//重载+运算符，要求两个矩阵的大小相同
	Matrix & operator + (const Matrix &a) {
		int i, j;
		if (row != a.row || col != a.col) {
			printf("Unmatch Matrix!\n");
			return *this;
		}
		if (temp != NULL) delete temp;
		temp = new Matrix(row, col, modnum);
		for (i = 0; i < row; i++) {
			for (j = 0; j < col; j++) {
				temp->data[i][j] = data[i][j] + a.data[i][j];
				if (modnum > 0) {
					temp->data[i][j] = mod(temp->data[i][j]);
				}
			}
		}
		return *temp;
	}
	//重载-运算符，要求两个矩阵的大小相同
	Matrix & operator - (const Matrix &a) {
		int i, j;
		if (row != a.row || col != a.col) {
			printf("Unmatch Matrix!\n");
			return *this;
		}
		if (temp != NULL) delete temp;
		temp = new Matrix(row, col, modnum);
		for (i = 0; i < row; i++) {
			for (j = 0; j < col; j++) {
				temp->data[i][j] = data[i][j] - a.data[i][j];
				if (modnum > 0) {
					temp->data[i][j] = mod(temp->data[i][j] + modnum);
				}
			}
		}
		return *temp;
	}
	//重载*运算符，要求矩阵a的列数等于b的行数
	Matrix & operator * (const Matrix &a) {
		int i, j, k;
		T tmp;
		if (col != a.row) {
			printf("Unmatch Matrix!\n");
			return *this;
		}
		if (temp != NULL) delete temp;
		temp = new Matrix(row, a.col, modnum);
		for (i = 0; i < row; i++) {
			for (j = 0; j < a.col; j++) {
				tmp = 0;
				for (k = 0; k < a.row; k++) {
					tmp += data[i][k] * a.data[k][j];
					if (modnum > 0) {
						tmp = mod(tmp);
					}
				}
				temp->data[i][j] = tmp;
			}
		}
		return *temp;
	}
	//重载^运算符，要求矩阵的列数等于行数
	Matrix & operator ^ (const int a) {
		int i, j;
		if (row != col) {
			printf("No n*n matrix!\n");
			return *this;
		}
		if (a < 0) {
			printf("Invalid a(%d)!\n", a);
			return *this;
		}
		if (temp != NULL) delete temp;
		temp = new Matrix(row, col, modnum);
		for (i = 0; i < row; i++) { //单位方阵 
			for (j = 0; j < col; j++) {
				if (i == j)temp->data[i][j] = 1;
				else temp->data[i][j] = 0;
			}
		}
		for (i = a, j = 0; i > 0; i >>= 1) j++;
		for (i = j - 1; i >= 0; i--) {
			if (a & (1 << i)) {
				*temp = *temp * *temp * (*this);
			}
			else {
				*temp = *temp * *temp;
			}
		}
		return *temp;
	}
	//重载求模函数，对int, long, long long, float, double都有效 
	int mod(int i) {
		return i % modnum;
	}
	long mod(long i) {
		return i % modnum;
	}
	long long mod(long long i) {
		return i % modnum;
	}
	float mod(float i) {
		return fmod(i, modnum);
	}
	double mod(double i) {
		return fmod(i, modnum);
	}
};