
/**************************************************
* File name: main.cc
* Author: by-zhang
* Description: ECDSA
* GitHub：https://github.com/by-zhang/ECDSA
**************************************************/
#include <iostream>
#include "ecdsa.h"
#include <cstring>

using namespace std;

int main()

{
	Ecdsa member1;

	char option, option1;

	//数字签名与验签部分
	
	cout<< "\t\t\t\t\t请选择数字签名方式：" << endl << endl;
	cout<<"\t\t\tA：ECDSA256 + SHA256\tB:ECDSA384 + SHA512\t C: SM2" << endl<<endl;
	cout<<"\t\t\t你的选择:";
	cin >> option;
	cout << endl << endl;

	if (option == 'a') {
		member1.main256();
	}
	else if (option == 'b') {
		member1.main384();
	}
	else if (option == 'c') {
		member1.SM2main();
	}

	else {
		cout << "\t\t选择无效，请重新选择";
		exit(3);
	}
	
	cout << endl;
	cout << endl;
	
	//X509证书打印部分
	cout << "您是否想进行X509证书生成？" << "  " << "y:是--n:否" << endl;
	cout << "选择： ";
	cin >> option1;
	cout << endl;
	cout << endl;

	if (option1 == 'y') {
		member1.Scriptmain();
		member1.X509main();
	}
	else if (option1 == 'n') {
		exit(1);
	}
	else
	{
		cout << "选择错误!!!" << endl;
		exit(3);
	}
	return 0;
}