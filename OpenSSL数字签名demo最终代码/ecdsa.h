
/**************************************************
* File name: ecdsa.cc
* Author: by-zhang
* Description: ECDSA
* GitHub：https://github.com/by-zhang/ECDSA
**************************************************/

#ifndef _EC_H
#define _EC_H
#include <iostream>
#include <iomanip>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include<fstream>
#include <string>
#include <vector>
#include <string.h>
#include <stdlib.h>
#include<stdio.h>
#include<openssl/err.h>
#include <sstream>

//头文件，就是建立了一个椭圆类
using namespace std;

class Ecdsa
{
private:
	EC_KEY* key;
	EC_KEY* p_key;
	const unsigned char* priv_b;
	unsigned int priv_b_length;
	unsigned char* pub_uncom;
	unsigned int pub_uncom_length;
	unsigned char* pub_com;
	unsigned int pub_com_length;
	string buffer;
	string buffer1;

	int setPriv256(const unsigned char*);
	int setPriv384(const unsigned char*);
	int setPub256();
	int setPub384();
	//string sha256(unsigned char*, const char*, unsigned int);
	string sha256(const char*, unsigned int);
	string sha512(const char*, unsigned int);

public:
	int newPair256(const unsigned char*);
	int newPair384(const unsigned char*);
	int sign256(unsigned char**, unsigned int*, const char*, unsigned int);
	int sign384(unsigned char**, unsigned int*, const char*, unsigned int);
	int verify256(const unsigned char*, unsigned int, const char*, unsigned int);
	int verify384(const unsigned char*, unsigned int, const char*, unsigned int);
	int print256();
	int print384();
	void printHash256();
	void printHash256Verify();
	void printHash384();
	void printHash384Verify();
	const char* returnFileContent();
	const char* returnFileContent1();
	void main384();
	void main256();
	int SM2main();
	void X509main();
	void Scriptmain();

};
#endif#pragma once
