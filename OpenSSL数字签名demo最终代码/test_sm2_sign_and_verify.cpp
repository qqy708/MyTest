
/**************************************************
* File name: test_sm2_sign_and_verify.c
* Author: HAN Wei
* Author's blog: https://blog.csdn.net/henter/
* Date: Nov 20th, 2018
* Description: implement SM2 sign data and verify
	signature test functions

	GitHub：https://github.com/greendow/SM2-signature-creation-and-verification
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
//SM2签名验签需要的变量，包括消息，消息长度，一个结构体来存储私钥和公钥（坐标点），这里用了一个namespace来存放这些东西，接下来的签名函数和验签函数需要用到
namespace own {
	string buffer1;
	string buffer2;

	SM2_KEY_PAIR key_pair;//结构体变量，里面存放着公钥和私钥，数据类型为字符数组
	SM2_SIGNATURE_STRUCT sm2_sig;//存储签名的结构体变量，由于椭圆曲线最终的签名是一个坐标点（R,S），所以需要两个数组来分别存储R和S
	const unsigned char* msg;//存储消息的数据类型，这里的消息是指从文件读取来的消息，用字符串来表示，msg只为了签名函数用
	const unsigned char* msg1;//msg1同msg一样，但是只是被验签函数所用
	unsigned int msg_len;//消息msg长度
	unsigned int msg_len1;//消息msg1长度
	int i;
}
using namespace own;

//密钥生成并且打印
void SM2keypair(void) {

	int error_code;
	if (error_code = sm2_create_key_pair(&key_pair))//调用生成密钥的函数
	{
		printf("\t\t创建密钥失败！\n");
	}
	printf("\t\t创建密钥成功!\n\n");
	printf("\t\tSM2私钥为: ");
	for (i = 0; i < sizeof(key_pair.pri_key); i++)
	{
		printf("0x%x  ", key_pair.pri_key[i]);
	}
	printf("\n\n");
	printf("\t\tSM2公钥为: ");
	for (i = 0; i < sizeof(key_pair.pub_key); i++)
	{
		printf("0x%x  ", key_pair.pub_key[i]);
	}
	printf("\n\n");

}
//签名端读取文件函数
void ReadFile(void) {

	char* filename = (char*)malloc(sizeof(char) * 10);//filename是为了存储读取文件的名字
	cout << "\t\t请输入要签名的文件名:";
	cin >> filename;
	cout << endl;

	FILE* fptr = fopen(filename, "r");//利用文件指针指向要打开的文件
	int c;
	vector<char> store;//容器存储文件内容
	ifstream input_file(filename);

	if (!input_file.is_open()) {
		cerr << "找不到文件 - '"
			<< filename << "'" << endl;
		cerr << "打开文件失败！";
		exit(0);
	}
	input_file.close();

	while (c = fgetc(fptr), c != EOF) {//while循环来将文件里的内容一个字符一个字符的读取，存储到容器store里面
		store.push_back(c);
	}
	fclose(fptr);

	for (int i = 0; i < store.size(); i++) {
		buffer1 += store[i];//将容器store里存储的内容放到string buffer里面
	}
	const char* fileContent = buffer1.c_str();
	msg = (const unsigned char*)fileContent;//将读取的文件传输到数据类型为const unsigned char* msg上，用于签名
	msg_len = (unsigned int)(strlen((char*)msg));//记录消息（字符串长度）
}

//验证端读取文件函数，与签名端一样
void ReadFileVerify(void) {

	char* filename = (char*)malloc(sizeof(char) * 10);//filename是为了存储读取文件的名

	cout << "\t\t请输入要验签的文件名:";
	cin >> filename;
	cout << endl;

	FILE* fptr = fopen(filename, "r");//利用文件指针指向要打开的文件
	int c;
	vector<char> store;//容器存储文件内容
	ifstream input_file(filename);

	if (!input_file.is_open()) {
		cerr << "找不到文件 - '"
			<< filename << "'" << endl;
		cerr << "打开文件失败！";
		exit(0);
	}
	input_file.close();

	while (c = fgetc(fptr), c != EOF) {//while循环来将文件里的内容一个字符一个字符的读取，存储到容器store里面
		store.push_back(c);
	}
	fclose(fptr);

	for (int i = 0; i < store.size(); i++) {
		buffer2 += store[i];//将容器store里存储的内容放到string buffer里面
	}
	const char* fileContent = buffer2.c_str();
	msg1 = (const unsigned char*)fileContent;//将读取的文件传输到数据类型为const unsigned char* msg上，用于验签
	msg_len1 = (unsigned int)(strlen((char*)msg1));

}
//签名函数
int sm2_sign(void)
{
	int error_code;
	ReadFile();
	string ID;
	cout << "\t\t请输入用户ID:";
	cin >> ID;
	cout << endl;

	const unsigned char* user_id;
	unsigned int user_id_len;

	const char* userID = ID.c_str();

	user_id = (const unsigned char*)userID;
	user_id_len = (unsigned int)(strlen((char*)user_id));


	if (error_code = sm2_sign_data(msg,//这里签名需要消息（字符串），消息长度，用户自定义的ID，公钥以及私钥，还有一个空的结构体变量sm2_sig用来存储签名
		msg_len,
		user_id,
		user_id_len,
		key_pair.pub_key,
		key_pair.pri_key,
		&sm2_sig))
	{
		printf("SM2签名创建失败!\n");
		return error_code;
	}
	printf("\t\tSM2签名生成完成!");
	printf("\n\n");
	printf("\t\tSM2签名为:");
	printf("\n\n");
	printf("\t\tR坐标点: ");

	for (i = 0; i < sizeof(sm2_sig.r_coordinate); i++)
	{
		printf("0x%x  ", sm2_sig.r_coordinate[i]);
	}
	printf("\n\n");
	printf("\t\tS坐标点: ");

	for (i = 0; i < sizeof(sm2_sig.s_coordinate); i++)
	{
		printf("0x%x  ", sm2_sig.s_coordinate[i]);
	}
	printf("\n\n");


	return 0;
}

//验签函数
int sm2_verify(void) {
	int error_code;
	ReadFileVerify();

	string ID;
	cout << "\t\t请输入用户ID:";
	cin >> ID;
	cout << endl;

	const unsigned char* user_id1;
	unsigned int user_id_len1;

	const char* userID = ID.c_str();

	user_id1 = (const unsigned char*)userID;
	user_id_len1 = (unsigned int)(strlen((char*)user_id1));

	if (error_code = sm2_verify_sig(msg1,//验签函数需要消息，消息长度，用户自定义的ID，公钥以及存有签名的结构体sm2.sig
		msg_len1,
		user_id1,
		user_id_len1,
		key_pair.pub_key,
		&sm2_sig))

	{
		printf("\t\tSM2验签失败!\n\n");
		return error_code;
	}
	printf("\t\tSM2验签成功!\n\n");
	return 0;
}