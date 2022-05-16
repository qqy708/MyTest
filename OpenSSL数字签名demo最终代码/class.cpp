
/**************************************************
* File name: class.cpp
* Author: SongXiaotong
* Description: websecurity-course
* GitHub£ºhttps://github.com/SongXiaotong/websecurity-course/blob/master/x.509/code/README.md
**************************************************/

#include <iostream>
#include <cstring>
using namespace std;

class TbsCertificate {
public:
	string version;
	string serialNumber;
	string signature[2];// algorithm parameters
	string issuer_[6][2];
	string validity[20];
	string subject_[6][2];
	string subjectPublicKeyInfo[3];// algorithm parameters Pkey
	string issuerUniqueID;
	string subjectUniqueID;
	string extensions;
};

class X509cer {
public:
	TbsCertificate cat;
	string casa[2];
	string casv;
};