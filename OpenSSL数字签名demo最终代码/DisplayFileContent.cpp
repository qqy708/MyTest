#include "ecdsa.h"

//此函数是将文件内容读取然后以 const char* 数据类型保存起来，返回文件内容
const char* Ecdsa::returnFileContent() {
	const char* buffer1 = buffer.c_str();
	return buffer1;
}
const char* Ecdsa::returnFileContent1() {
	const char* buffer2 = buffer1.c_str();
	return buffer2;
}