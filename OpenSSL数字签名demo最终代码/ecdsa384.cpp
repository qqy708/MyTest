
/**************************************************
* File name: ecdsa.cc
* Author: by-zhang
* Description: ECDSA
* GitHub：https://github.com/by-zhang/ECDSA
**************************************************/

#include "ecdsa.h"
#define SHA512_DIGEST_LENGTH 64
//密钥对生成
int Ecdsa::newPair384(const unsigned char* priv_b)
{
	EC_KEY* key;
	BIGNUM* priv;
	BN_CTX* ctx;
	const EC_GROUP* group;
	EC_POINT* pub;

	this->setPriv384(priv_b);

	/** create a ec keypair **/
	key = EC_KEY_new_by_curve_name(NID_brainpoolP384r1);

	cout << "\t\t椭圆曲线NID_brainpoolP384r11生成的密钥对为: " << key << endl;

	/** convert priv_b to a 32-byte BIGNUM **/
	priv = BN_new();
	BN_bin2bn(this->priv_b, 32, priv);//!
	//cout << priv;

	/** insert private key to key pair **/
	EC_KEY_set_private_key(key, priv);
	cout << priv << endl;

	/** derive public key, and insert public key to key pair **/
	ctx = BN_CTX_new();
	BN_CTX_start(ctx);

	group = EC_KEY_get0_group(key);
	pub = EC_POINT_new(group);
	EC_POINT_mul(group, pub, priv, NULL, NULL, ctx);
	EC_KEY_set_public_key(key, pub);
	this->key = key;
	this->setPub384();

	/** release resources **/
	EC_POINT_free(pub);
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	BN_clear_free(priv);

	return 0;
}


using namespace std;

//sha256函数生成一个数据类型为string的字符串，长度为64个bit
/*
string sha256(const string str)
{
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, str.c_str(), str.size());
	SHA256_Final(hash, &sha256);
	stringstream ss;

	for (int i = 0; i < SHA512_DIGEST_LENGTH; i++)
	{
		ss << hex << setw(2) << setfill('0') << (int)hash[i];
	}
	return ss.str();
}*/

//printHash函数将文件内容打印出来
void Ecdsa::printHash384() {

	char* filename = (char*)malloc(sizeof(char) * 10);//filename是为了存储读取文件的名字
	cout << "\t\t请输入要签名的文件名: ";
	cin >> filename;
	cout << endl;
	FILE* fptr = fopen(filename, "r");//利用文件指针指向要打开的文件
	int c;
	//string filename("input.txt");
	vector<char> store;//容器存储文件内容
	ifstream input_file(filename);

	if (!input_file.is_open()) {
		cerr << "找不到文件 - '"
			<< filename << "'" << endl;
		cerr << "打开文件失败！";
		exit(0);
	}
	input_file.close();

	//while (getline(input_file, line)) {
		//store.push_back(line);
	//}

	while (c = fgetc(fptr), c != EOF) {//while循环来将文件里的内容一个字符一个字符的读取，存储到容器store里面
		store.push_back(c);
	}
	fclose(fptr);

	for (int i = 0; i < store.size(); i++) {
		buffer += store[i];//将容器store里存储的内容放到string buffer里面
	}
	//cout << "\t\t第一次的文件内容为:\t" << buffer << endl << endl;
}

//验签端的函数，首先输入文件名，其次展示文件内容
void Ecdsa::printHash384Verify() {

	char* filename = (char*)malloc(sizeof(char) * 10);//filename是为了存储读取文件的名字
	cout << "\t\t请输入要验签的文件名: ";
	cin >> filename;
	cout << endl;
	FILE* fptr = fopen(filename, "r");//利用文件指针指向要打开的文件
	int c;
	//string filename("input.txt");
	vector<char> store;//容器存储文件内容
	string line;
	ifstream input_file(filename);

	if (!input_file.is_open()) {
		cerr << "Could not open the file - '"
			<< filename << "'" << endl;
		cerr << "failed to open file";
		exit(0);
	}
	input_file.close();

	//while (getline(input_file, line)) {
		//store.push_back(line);
	//}

	while (c = fgetc(fptr), c != EOF) {//while循环来将文件里的内容一个字符一个字符的读取，存储到容器store里面
		store.push_back(c);
	}
	fclose(fptr);

	for (int i = 0; i < store.size(); i++) {
		buffer1 += store[i];//将容器store里存储的内容放到string buffer里面
	}
	//cout << "\t\t接收到的文件内容为:\t" << buffer1 << endl << endl;
}

//此函数将文件内容进行SHA512哈希并且展示哈希值，文件内容为const char* 类型的数据
int Ecdsa::sign384(unsigned char** der, unsigned int* dlen, const char* message, unsigned int len)
{
	ECDSA_SIG* signature;//结构体ECDSA_SIG是头文件ec.h里自带的定义的结构体，这里是这个结构体的指针
	unsigned int der_len;
	unsigned char* der_copy;

	string dst = sha512(message, len);
	cout << "\t\t文件的SHA512哈希值为:\t" << dst << endl << endl;
	const unsigned char* dst1 = (const unsigned char*)dst.c_str();
	//this->sha256(digest, message, len);//将空的digest传到生成一堆乱码的那个哈希函数里
	signature = ECDSA_do_sign(dst1, sizeof(dst1), this->key);//此时digest里有内容了，即一堆乱码，然后这个函数签这对乱码，生成签名，它返回的是一个已经定义了的结构体指针

	//cout << "r: " << BN_bn2hex(signature->r) << endl;//这里其实是签名形成的坐标（r,s),但是如果去掉注释，会有错误，原因是signature->r这个表达不合法，报错的内容是signature指向的结构体ECDSA_SIG（typedef后）没有内容，结构体ECDSA_SIG
	// 只是被forward declare了，里面有哪些数据并没有声明，所以报错内容是signature这个指针指向一个不完整结构体，原因应该是我们用的openssl版本在升级后，隐藏了一些内置的和椭圆曲线相关的结构体，出于安全考虑
	// 但是坐标（r,s)才是最标准的签名格式，最标准的签名就是一个坐标点，而不是单纯的字符串
	//cout << "s: " << BN_bn2hex(signature->s) << endl;

	*dlen = ECDSA_size(this->key);
	*der = (unsigned char*)calloc(*dlen, sizeof(unsigned char));
	der_copy = *der;
	i2d_ECDSA_SIG(signature, &der_copy);

	cout << "\t\t对哈希值的签名为:\t" << signature << endl << endl;//同上，测试一下看看而已
	ECDSA_SIG_free(signature);//签名被释放掉了，至此签名过程完成

	return 0;
}
//验证签名的函数，里面需要的参数和sign384非常相似，而且都是需要传一个数据类型为const char*的文件内容和这个文件内容的字符串长度
int Ecdsa::verify384(const unsigned char* der, unsigned int der_len, const char* message, unsigned int len)
{
	const unsigned char* der_copy;
	ECDSA_SIG* signature;
	//unsigned char digest[32];//这个数据是用来存储哈希值的（生成一堆乱码的那个哈希函数的输出，就是存在这个digest里
	int res;
	der_copy = der;

	signature = d2i_ECDSA_SIG(NULL, &der_copy, der_len);//这里用的签名的函数和sign里不一样，具体原因还没有仔细看，但是openssl里有解释

	//this->sha256(message, len);//再次进行哈希生成一堆乱码
	string dst = sha512(message, len);
	cout << "\t\t再次查看文件的SHA512哈希值为:\t" << dst << endl << endl;
	const unsigned char* dst1 = (const unsigned char*)dst.c_str();
	/** 1:verified. 2:not verified. 3:library error. **/

	res = ECDSA_do_verify(dst1, sizeof(dst1), signature, this->p_key);//此时digest里有内容了，即一堆乱码，然后这个函数签这对乱码，生成签名，它返回的是一个已经定义了的结构体指针

	cout << "\t\t再次查看对哈希值的签名为:\t" << signature << endl << endl;//同上，测试一下看看而已

	return res;//如果是1，签名验签成功，如果是其他数字，则失败
}
//这个函数是打印出公钥和私钥
int Ecdsa::print384()
{
	cout << "\t\t私钥为： (" << this->priv_b_length << "bytes) #:" << endl;
	for (int t = 0; t < this->priv_b_length; t++)
	{
		cout << hex << setw(2) << setfill('0') << (unsigned int)this->priv_b[t];
	}
	cout << endl << endl;
	cout << dec << "\t\t未压缩的公钥为： (" << this->pub_uncom_length << "bytes) #:" << endl;
	for (int t = 0; t < this->pub_uncom_length; t++)
	{
		cout << hex << setw(2) << setfill('0') << (unsigned int)this->pub_uncom[t];
	}
	cout << endl << endl;
	cout << dec << "\t\t压缩后的公钥为： (" << this->pub_com_length << "bytes) #:" << endl << endl;
	for (int t = 0; t < this->pub_com_length; t++)
	{
		cout << hex << setw(2) << setfill('0') << (unsigned int)this->pub_com[t];
	}
	cout << endl << endl;;
	return 0;
}
//生成私钥
int Ecdsa::setPriv384(const unsigned char* priv_b)
{
	this->priv_b = priv_b;
	this->priv_b_length = 64;//!
	return 0;
}
//生成公钥
int Ecdsa::setPub384()
{
	unsigned char* pub_copy;
	const unsigned char* pub_bytes_copy;
	/** uncompressed form **/
	EC_KEY_set_conv_form(this->key, POINT_CONVERSION_UNCOMPRESSED);
	this->pub_uncom_length = i2o_ECPublicKey(this->key, NULL);
	this->pub_uncom = (unsigned char*)calloc(this->pub_uncom_length, sizeof(unsigned char));
	pub_copy = this->pub_uncom;
	if (i2o_ECPublicKey(this->key, &pub_copy) != this->pub_uncom_length) {
		cout << "error:Unable to decode public key(uncompressed)" << endl << endl;
		return -1;
	}
	/** compressed form **/
	EC_KEY_set_conv_form(this->key, POINT_CONVERSION_COMPRESSED);
	this->pub_com_length = i2o_ECPublicKey(this->key, NULL);
	this->pub_com = (unsigned char*)calloc(this->pub_com_length, sizeof(unsigned char));
	pub_copy = this->pub_com;
	if (i2o_ECPublicKey(this->key, &pub_copy) != this->pub_com_length) {
		cout << "error:Unable to decode public key(compressed)" << endl << endl;
		return -1;
	}
	/** store EC_KEY formed public key **/
	this->p_key = EC_KEY_new_by_curve_name(NID_brainpoolP384r1);
	pub_bytes_copy = this->pub_com;
	o2i_ECPublicKey(&this->p_key, &pub_bytes_copy, this->pub_com_length);
	return 0;
}

//SHA512函数进行哈希和填充
string Ecdsa::sha512(const char* message, unsigned int len) {

	unsigned char digest1[SHA512_DIGEST_LENGTH];//空的char数组，用来装SHA512的哈希值
	SHA512_CTX ctx;//openSSL里定义的一个SHA512结构体
	SHA512_Init(&ctx);//此函数初始化这个结构体
	SHA512_Update(&ctx, message, len);//此函数是进行哈希运算的函数，可以被连续调用
	SHA512_Final(digest1, &ctx);//将最终的哈希结果存储在digest1这个数组里，此时的哈希值是一堆乱码，我们必须转化成16进制格式
	stringstream ss;
	//for 循环来实现填充，并且将digest1里面的乱码转换成16进制格式，setw()和setfill()分别是填充宽度和填充内容
	for (int i = 0; i < SHA512_DIGEST_LENGTH; i++)
	{
		ss << hex << setw(2) << setfill('0') << (int)digest1[i];
	}

	string finalHash = ss.str();//将填充好哈希值转换成string格式
	return finalHash;
}
