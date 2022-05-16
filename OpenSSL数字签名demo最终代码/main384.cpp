
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

//SHA512����Բ����P384r1�ĺ���
void Ecdsa::main384()
{
	Ecdsa ec2;

	unsigned char priv_bytes[64] = {
		0x16, 0x26, 0x07, 0x83, 0xe4, 0x0b, 0x16, 0x73,
		0x16, 0x73, 0x62, 0x2a, 0xc8, 0xa5, 0xb0, 0x45,
		0xfc, 0x3e, 0xa4, 0xaf, 0x70, 0xf7, 0x27, 0xf3,
		0xf9, 0xe9, 0x2b, 0xdd, 0x3a, 0x1d, 0xdc, 0x42,
		0x16, 0x26, 0x07, 0x83, 0xe4, 0x0b, 0x16, 0x73,
		0x16, 0x73, 0x62, 0x2a, 0xc8, 0xa5, 0xb0, 0x45,
		0xfc, 0x3e, 0xa4, 0xaf, 0x70, 0xf7, 0x27, 0xf3,
		0xf9, 0xe9, 0x2b, 0xdd, 0x3a, 0x1d, 0xdc, 0x42
	};

	ec2.newPair384(priv_bytes);
	ec2.print384();
	unsigned char digest[64];
	int res;//�洢��ǩ�������ص�����ֵ
	unsigned char* der;
	unsigned int der_len;

	ec2.printHash384();

	const char* message = ec2.returnFileContent();//����һ����������Ϊconst char*�Ĵ洢�ļ����ݵ��ַ���
	const char* add = "hellofromshadsad45639qwe!@#$%^&*";//�������������һ����ǩʧ�ܣ����԰�res = ec.verify(der, der_len, message3, strlen(message3));���message3����add�������ǩ�������0����ʧ��
	ec2.sign384(&der, &der_len, message, strlen(message));//callǩ������������������Ϊconst char*�Ĵ洢�ļ����ݵ��ַ�������sign����

	ec2.printHash384Verify();
	const char* message1 = ec2.returnFileContent1();
	res = ec2.verify384(der, der_len, message1, strlen(message1));//��ǩ�����ļ������Լ��ļ������ַ������ȴ���verify����������ǩ

	if (res == 1) {
		cout << "\t\t��֤ǩ���Ľ��Ϊ:  " << "�ɹ�" << endl << endl;//��ǩ�����1���ʾ��ǩ�ɹ�
	}
	else {
		cout << "\t\t��֤ǩ���Ľ��Ϊ:  " << "ʧ��" << endl << endl;//��ǩ�����0���ʾ��ǩʧ��

	}
}