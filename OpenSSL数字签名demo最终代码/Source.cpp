
/**************************************************
* File name: main.cc
* Author: by-zhang
* Description: ECDSA
* GitHub��https://github.com/by-zhang/ECDSA
**************************************************/
#include <iostream>
#include "ecdsa.h"
#include <cstring>

using namespace std;

int main()

{
	Ecdsa member1;

	char option, option1;

	//����ǩ������ǩ����
	
	cout<< "\t\t\t\t\t��ѡ������ǩ����ʽ��" << endl << endl;
	cout<<"\t\t\tA��ECDSA256 + SHA256\tB:ECDSA384 + SHA512\t C: SM2" << endl<<endl;
	cout<<"\t\t\t���ѡ��:";
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
		cout << "\t\tѡ����Ч��������ѡ��";
		exit(3);
	}
	
	cout << endl;
	cout << endl;
	
	//X509֤���ӡ����
	cout << "���Ƿ������X509֤�����ɣ�" << "  " << "y:��--n:��" << endl;
	cout << "ѡ�� ";
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
		cout << "ѡ�����!!!" << endl;
		exit(3);
	}
	return 0;
}