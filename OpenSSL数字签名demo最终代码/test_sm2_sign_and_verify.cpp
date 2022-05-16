
/**************************************************
* File name: test_sm2_sign_and_verify.c
* Author: HAN Wei
* Author's blog: https://blog.csdn.net/henter/
* Date: Nov 20th, 2018
* Description: implement SM2 sign data and verify
	signature test functions

	GitHub��https://github.com/greendow/SM2-signature-creation-and-verification
**************************************************/

#include <stdio.h>
#include <string.h>
#include <sstream>
#include<fstream>
#include <string>
#include <vector>
#include <stdlib.h>
#include <iostream>
#include <iomanip>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include<openssl/err.h>

#include "sm2_create_key_pair.h"
#include "sm2_sign_and_verify.h"
#include "test_sm2_sign_and_verify.h"
using namespace std;
//SM2ǩ����ǩ��Ҫ�ı�����������Ϣ����Ϣ���ȣ�һ���ṹ�����洢˽Կ�͹�Կ������㣩����������һ��namespace�������Щ��������������ǩ����������ǩ������Ҫ�õ�
namespace own {
	string buffer1;
	string buffer2;

	SM2_KEY_PAIR key_pair;//�ṹ��������������Ź�Կ��˽Կ����������Ϊ�ַ�����
	SM2_SIGNATURE_STRUCT sm2_sig;//�洢ǩ���Ľṹ�������������Բ�������յ�ǩ����һ������㣨R,S����������Ҫ�����������ֱ�洢R��S
	const unsigned char* msg;//�洢��Ϣ���������ͣ��������Ϣ��ָ���ļ���ȡ������Ϣ�����ַ�������ʾ��msgֻΪ��ǩ��������
	const unsigned char* msg1;//msg1ͬmsgһ��������ֻ�Ǳ���ǩ��������
	unsigned int msg_len;//��Ϣmsg����
	unsigned int msg_len1;//��Ϣmsg1����
	int i;
}
using namespace own;

//��Կ���ɲ��Ҵ�ӡ
void SM2keypair(void) {

	int error_code;
	if (error_code = sm2_create_key_pair(&key_pair))//����������Կ�ĺ���
	{
		printf("\t\t������Կʧ�ܣ�\n");
	}
	printf("\t\t������Կ�ɹ�!\n\n");
	printf("\t\tSM2˽ԿΪ: ");
	for (i = 0; i < sizeof(key_pair.pri_key); i++)
	{
		printf("0x%x  ", key_pair.pri_key[i]);
	}
	printf("\n\n");
	printf("\t\tSM2��ԿΪ: ");
	for (i = 0; i < sizeof(key_pair.pub_key); i++)
	{
		printf("0x%x  ", key_pair.pub_key[i]);
	}
	printf("\n\n");

}
//ǩ���˶�ȡ�ļ�����
void ReadFile(void) {

	char* filename = (char*)malloc(sizeof(char) * 10);//filename��Ϊ�˴洢��ȡ�ļ�������
	cout << "\t\t������Ҫǩ�����ļ���:";
	cin >> filename;
	cout << endl;

	FILE* fptr = fopen(filename, "r");//�����ļ�ָ��ָ��Ҫ�򿪵��ļ�
	int c;
	vector<char> store;//�����洢�ļ�����
	ifstream input_file(filename);

	if (!input_file.is_open()) {
		cerr << "�Ҳ����ļ� - '"
			<< filename << "'" << endl;
		cerr << "���ļ�ʧ�ܣ�";
		exit(0);
	}
	input_file.close();

	while (c = fgetc(fptr), c != EOF) {//whileѭ�������ļ��������һ���ַ�һ���ַ��Ķ�ȡ���洢������store����
		store.push_back(c);
	}
	fclose(fptr);

	for (int i = 0; i < store.size(); i++) {
		buffer1 += store[i];//������store��洢�����ݷŵ�string buffer����
	}
	const char* fileContent = buffer1.c_str();
	msg = (const unsigned char*)fileContent;//����ȡ���ļ����䵽��������Ϊconst unsigned char* msg�ϣ�����ǩ��
	msg_len = (unsigned int)(strlen((char*)msg));//��¼��Ϣ���ַ������ȣ�
}

//��֤�˶�ȡ�ļ���������ǩ����һ��
void ReadFileVerify(void) {

	char* filename = (char*)malloc(sizeof(char) * 10);//filename��Ϊ�˴洢��ȡ�ļ�����

	cout << "\t\t������Ҫ��ǩ���ļ���:";
	cin >> filename;
	cout << endl;

	FILE* fptr = fopen(filename, "r");//�����ļ�ָ��ָ��Ҫ�򿪵��ļ�
	int c;
	vector<char> store;//�����洢�ļ�����
	ifstream input_file(filename);

	if (!input_file.is_open()) {
		cerr << "�Ҳ����ļ� - '"
			<< filename << "'" << endl;
		cerr << "���ļ�ʧ�ܣ�";
		exit(0);
	}
	input_file.close();

	while (c = fgetc(fptr), c != EOF) {//whileѭ�������ļ��������һ���ַ�һ���ַ��Ķ�ȡ���洢������store����
		store.push_back(c);
	}
	fclose(fptr);

	for (int i = 0; i < store.size(); i++) {
		buffer2 += store[i];//������store��洢�����ݷŵ�string buffer����
	}
	const char* fileContent = buffer2.c_str();
	msg1 = (const unsigned char*)fileContent;//����ȡ���ļ����䵽��������Ϊconst unsigned char* msg�ϣ�������ǩ
	msg_len1 = (unsigned int)(strlen((char*)msg1));

}
//ǩ������
int sm2_sign(void)
{
	int error_code;
	ReadFile();
	string ID;
	cout << "\t\t�������û�ID:";
	cin >> ID;
	cout << endl;

	const unsigned char* user_id;
	unsigned int user_id_len;

	const char* userID = ID.c_str();

	user_id = (const unsigned char*)userID;
	user_id_len = (unsigned int)(strlen((char*)user_id));


	if (error_code = sm2_sign_data(msg,//����ǩ����Ҫ��Ϣ���ַ���������Ϣ���ȣ��û��Զ����ID����Կ�Լ�˽Կ������һ���յĽṹ�����sm2_sig�����洢ǩ��
		msg_len,
		user_id,
		user_id_len,
		key_pair.pub_key,
		key_pair.pri_key,
		&sm2_sig))
	{
		printf("SM2ǩ������ʧ��!\n");
		return error_code;
	}
	printf("\t\tSM2ǩ���������!");
	printf("\n\n");
	printf("\t\tSM2ǩ��Ϊ:");
	printf("\n\n");
	printf("\t\tR�����: ");

	for (i = 0; i < sizeof(sm2_sig.r_coordinate); i++)
	{
		printf("0x%x  ", sm2_sig.r_coordinate[i]);
	}
	printf("\n\n");
	printf("\t\tS�����: ");

	for (i = 0; i < sizeof(sm2_sig.s_coordinate); i++)
	{
		printf("0x%x  ", sm2_sig.s_coordinate[i]);
	}
	printf("\n\n");


	return 0;
}

//��ǩ����
int sm2_verify(void) {
	int error_code;
	ReadFileVerify();

	string ID;
	cout << "\t\t�������û�ID:";
	cin >> ID;
	cout << endl;

	const unsigned char* user_id1;
	unsigned int user_id_len1;

	const char* userID = ID.c_str();

	user_id1 = (const unsigned char*)userID;
	user_id_len1 = (unsigned int)(strlen((char*)user_id1));

	if (error_code = sm2_verify_sig(msg1,//��ǩ������Ҫ��Ϣ����Ϣ���ȣ��û��Զ����ID����Կ�Լ�����ǩ���Ľṹ��sm2.sig
		msg_len1,
		user_id1,
		user_id_len1,
		key_pair.pub_key,
		&sm2_sig))

	{
		printf("\t\tSM2��ǩʧ��!\n\n");
		return error_code;
	}
	printf("\t\tSM2��ǩ�ɹ�!\n\n");
	return 0;
}