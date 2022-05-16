
/**************************************************
* File name: main.cpp
* Author: SongXiaotong
* Description: websecurity-course
* GitHub：https://github.com/SongXiaotong/websecurity-course/blob/master/x.509/code/README.md
**************************************************/

#include <iostream>
#include <cstring>
#include "class.cpp"
#include "ecdsa.h"
using namespace std;

string s = "";
int time1, curr;
bool stop = 1;
bool btag = 1;
int n = 1;// {"ver", "seq", "sigalg", "iss", "time", "usr", "keyalg"};
int lasttype;
FILE* fp;
string sA[8][2] = { {"1.2.840.10040.4.1", "DSA"},{"1.2.840.10040.4.3", "sha1DSA"},
			{"1.2.840.113549.1.1.1", "RSA"},{"1.2.840.113549.1.1.2", "md2RSA"},{"1.2.840.113549.1.1.3", "md4RSA"},
			{"1.2.840.113549.1.1.4", "md5RSA"},{"1.2.840.113549.1.1.5", "sha1RSA"},{"1.2.840.113549.1.1.11", "sha256RSA"} };

string is[6][2] = { {"2.5.4.6", "国家 "},{"2.5.4.8", "省份 "},{"2.5.4.7", "城市 "},
			{"2.5.4.10", "公司名称 "},{"2.5.4.11", "部门名称 "},{"2.5.4.3", "常用名 "} };


X509cer ca_cer;
void init();
int tlv();
void output();
string timing(string s);

void Ecdsa::X509main() {
	init();
	tlv();
	output();
}
//init 函数读取X509证书，格式为ASN.1格式，即文件后缀名为.der
void init() {

	char* filename = (char*)malloc(sizeof(char) * 10);
	cout << "请输入X509证书文件名: ";
	cin >> filename;
	fp = fopen(filename, "rb");

	if (fp == NULL) {
		puts("can't open the file!");
		exit(0);
	}
}
//fill函数是用之前声明的全局变量string s来存储证书的各种信息，如序列号，发行者信息，证书主题信息等
void fill(int t) {
	if (n == 1 && t == 2) {
		if (s == "0")
			ca_cer.cat.version = "V1";
		else if (s == "1")
			ca_cer.cat.version = "V2";
		else
			ca_cer.cat.version = "V3";
		n++;
	}
	else if (n == 2 || t == 2) {
		n++;
		ca_cer.cat.serialNumber = s;
	}

	else if (n == 3 && t == 6) {
		for (int i = 0; i < 8; ++i) {
			if (s == sA[i][0]) {
				ca_cer.cat.signature[0] = sA[i][1];
				break;
			}
		}
	}

	else if (n == 3 && t == 5) {
		ca_cer.cat.signature[1] = s;
		n++;
	}
	else if (n == 4 && t == 6) {
		for (int i = 0; i < 6; ++i) {
			if (s == is[i][0]) {
				ca_cer.cat.issuer_[i][0] = is[i][1];
				ca_cer.cat.issuer_[i][0] += "--颁发者:  ";
				curr = i;
				break;
			}
		}
	}

	/*
	else if (n == 4 && t == 19) {
		ca_cer.cat.issuer_[curr][1] = s;
	}*/

	else if (t == 23) {
		ca_cer.cat.validity[n - 4] = timing(s);
		n++;
	}

	else if (n == 6 && t == 6) {
		for (int i = 0; i < 6; ++i) {
			if (s == is[i][0]) {
				// cout << s << " " << i << endl;
				ca_cer.cat.subject_[i][0] = is[i][1];
				ca_cer.cat.subject_[i][0] += "--证书主体:  ";
				curr = i;
				break;
			}
		}
		//	cout << s << "****" << endl;
		for (int i = 0; i < 30; ++i) {
			if (s == sA[i][0]) {
				ca_cer.cat.subjectPublicKeyInfo[0] = sA[i][1];
				n++;
				break;
			}
		}
	}
	else if (n == 6 && (t == 12 || t == 19))
		ca_cer.cat.subject_[curr][1] = s;
	else if (n == 7 && t == 5)
		ca_cer.cat.subjectPublicKeyInfo[1] = s;
	else if (n == 7 && t == 3)
		ca_cer.cat.subjectPublicKeyInfo[2] = s;
	else if (n == 7 && t == 6) {
		n++;
		for (int i = 0; i < 8; ++i) {
			if (s == sA[i][0]) {
				ca_cer.casa[0] = sA[i][1];
				break;
			}
		}
	}
	else if (n == 8 && t == 5)
		ca_cer.casa[1] = s;
	else if (n == 8 && t == 3) {
		ca_cer.casv = s;
		stop = 0; // stop the check
	}
	if (1 == 1 && n == 4) {
		ca_cer.cat.issuer_[curr][1] = s;
	}
}

void bitfill(int len) {
	s = "";
	int i = 0;
	for (int i = 0; i < len; ++i) {
		unsigned char tl = fgetc(fp);
		char ts2[10];
		sprintf(ts2, "%02x", (int)tl);
		s = s + ts2;
	}
}

//tlv即type，length,value，此函数每次读取证书的一个字节，然后读取相应长度，根据字节来判断数据类型是一表示一个序列号，还是公钥，还是签名等
int tlv() {
	if (stop == 0) {
		return 1000;
	}
	time1++;// time
	bool b = true;
	unsigned char type = fgetc(fp);// type
	unsigned char len0 = fgetc(fp);// len
	int len = len0;
	s = "";

	if (type < 0xa0) {// valu
		if (type == 1) {
			unsigned char vc = fgetc(fp);
			s = vc == 0 ? "FALSE" : "TRUE";
		}
		else if (type == 2 || type == 3 || type == 4) {
			if (len0 > 0x80) { // len > 7
				len = 0;
				for (int i = 0; i < len0 - 0x80; ++i)
					len = len * 256 + fgetc(fp);
			}// get the real length
			bitfill(len);
		}
		else if (type == 5) {
			s = "NULL";
		}
		else if (type == 6) {
			int d = fgetc(fp);
			char ts2[10];
			sprintf(ts2, "%d", d / 40);
			s = s + ts2 + ".";
			sprintf(ts2, "%d", d - d / 40 * 40);
			s = s + ts2;
			for (int i = 1; i < len0; ++i) {
				i--;
				int t = 0;
				while (1) {
					int tl = fgetc(fp);
					i++;
					bool b2 = false;
					if (tl & 0x80) {
						b2 = true;
						tl &= 0x7f;
					}
					t = t * 128 + tl;
					if (!b2) break;
				}
				sprintf(ts2, "%d", t);
				s = s + "." + ts2;
			}
			//           cout << s << endl; 
		}
		else if (type == 0x13 || type == 0x17 || type == 0x18 || type == 0x0c) {// 任意长度ascii字符串
			char ss[5000];
			fread(ss, 1, len0, fp);
			ss[len0] = '\0';
			s = ss;
		}
		else if (type == 0x30 || type == 0x31) {
			b = false;
			if (len0 > 0x80) {
				len = 0;
				len0 -= 0x80;
				unsigned char tl;
				for (int i = 0; i < len0; ++i) {
					tl = fgetc(fp);
					len = len * 256 + tl;
				}
			}
			int dlen = len;
			while (dlen > 0) {
				dlen -= tlv();
			}
		}
		else {
			//printf("the cer has errors!\n");
			return len;
		}
	}
	else {
		b = false;
		if (type == 0xff) {
			output();
			exit(1);
		}
		if (len0 > 0x80) {
			int tn2 = len0 - 0x80;
			unsigned char tl;
			len = 0;
			for (int i = 0; i < tn2; ++i) {
				tl = fgetc(fp);
				len = len * 256 + tl;
			}
		}
		if (btag) {
			if (time1 == 67)
				fseek(fp, len, SEEK_CUR);
			else
				tlv();
		}
	}
	if (b)
		fill(type);

	return len;
}

//此函数是读取X509证书上的时间（格式为年-月-日-时-分-秒）
string timing(string s) {
	string res0;
	char res[19] = { '2', '0', s[0], s[1], '.', s[2], s[3], '.', s[4], s[5], ' ', s[6], s[7], ':', s[8], s[9], ':', s[10], s[11] };

	for (int i = 0; i < 19; i++) {
		res0.push_back(res[i]);
	}

	return res0;
}

//打印X509证书的内容
void output() {
	cout << "****************************************************X509证书内容如下***************************************************" << endl;
	cout << endl;
	cout << "版本:  " << ca_cer.cat.version << endl;
	cout << endl;
	cout << "序列号:  " << ca_cer.cat.serialNumber << endl;
	cout << endl;
	cout << "签名算法:  " << ca_cer.cat.signature[0] << endl;
	cout << endl;
	cout << "签名算法的参数:  " << ca_cer.cat.signature[1] << endl;
	cout << endl;
	cout << "签发者标识信息（如下）:  " << endl;
	cout << endl;
	for (int i = 0; i < 6; ++i) {
		if (ca_cer.cat.issuer_[i][0] == "")
			continue;
		cout << ca_cer.cat.issuer_[i][0] << " " << ca_cer.cat.issuer_[i][1] << endl;

	}
	cout << endl;
	cout << "有效期:  " << ca_cer.cat.validity[0] << "-" << ca_cer.cat.validity[1] << endl;
	cout << endl;

	cout << "使用者标识信息（如下）:  " << endl;
	cout << endl;
	for (int i = 0; i < 6; ++i) {
		if (ca_cer.cat.subject_[i][0] == "")
			continue;
		cout << ca_cer.cat.subject_[i][0] << " " << ca_cer.cat.subject_[i][1] << endl;

	}
	cout << endl;
	cout << "公钥的加密算法:  " << ca_cer.cat.subjectPublicKeyInfo[0] << endl;
	cout << endl;
	cout << "公钥的加密算法参数:  " << ca_cer.cat.subjectPublicKeyInfo[1] << endl;
	cout << endl;
	cout << "公钥数据:  " << ca_cer.cat.subjectPublicKeyInfo[2] << endl;
	cout << endl;
	cout << "签名算法的参数:  " << ca_cer.casa[1] << endl;
	cout << endl;
	cout << "签名结果:  " << ca_cer.casv << endl;
	cout << endl;
	cout << "*****************************************************************************************************************" << endl;
}