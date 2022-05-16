
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

//SHA512和椭圆曲线P384r1的函数
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
	int res;//存储验签函数返回的整数值
	unsigned char* der;
	unsigned int der_len;

	ec2.printHash384();

	const char* message = ec2.returnFileContent();//返回一个数据类型为const char*的存储文件内容的字符串
	const char* add = "hellofromshadsad45639qwe!@#$%^&*";//如果你想刻意测试一下验签失败，可以把res = ec.verify(der, der_len, message3, strlen(message3));里的message3换成add，最后验签结果就是0，即失败
	ec2.sign384(&der, &der_len, message, strlen(message));//call签名函数，把数据类型为const char*的存储文件内容的字符串传到sign里面

	ec2.printHash384Verify();
	const char* message1 = ec2.returnFileContent1();
	res = ec2.verify384(der, der_len, message1, strlen(message1));//验签，将文件内容以及文件内容字符串长度传到verify函数里面验签

	if (res == 1) {
		cout << "\t\t验证签名的结果为:  " << "成功" << endl << endl;//验签结果，1则表示验签成功
	}
	else {
		cout << "\t\t验证签名的结果为:  " << "失败" << endl << endl;//验签结果，0则表示验签失败

	}
}