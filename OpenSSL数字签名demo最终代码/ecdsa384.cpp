
/**************************************************
* File name: ecdsa.cc
* Author: by-zhang
* Description: ECDSA
* GitHub��https://github.com/by-zhang/ECDSA
**************************************************/

#include "ecdsa.h"
#define SHA512_DIGEST_LENGTH 64
//��Կ������
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

	cout << "\t\t��Բ����NID_brainpoolP384r11���ɵ���Կ��Ϊ: " << key << endl;

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

//sha256��������һ����������Ϊstring���ַ���������Ϊ64��bit
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

//printHash�������ļ����ݴ�ӡ����
void Ecdsa::printHash384() {

	char* filename = (char*)malloc(sizeof(char) * 10);//filename��Ϊ�˴洢��ȡ�ļ�������
	cout << "\t\t������Ҫǩ�����ļ���: ";
	cin >> filename;
	cout << endl;
	FILE* fptr = fopen(filename, "r");//�����ļ�ָ��ָ��Ҫ�򿪵��ļ�
	int c;
	//string filename("input.txt");
	vector<char> store;//�����洢�ļ�����
	ifstream input_file(filename);

	if (!input_file.is_open()) {
		cerr << "�Ҳ����ļ� - '"
			<< filename << "'" << endl;
		cerr << "���ļ�ʧ�ܣ�";
		exit(0);
	}
	input_file.close();

	//while (getline(input_file, line)) {
		//store.push_back(line);
	//}

	while (c = fgetc(fptr), c != EOF) {//whileѭ�������ļ��������һ���ַ�һ���ַ��Ķ�ȡ���洢������store����
		store.push_back(c);
	}
	fclose(fptr);

	for (int i = 0; i < store.size(); i++) {
		buffer += store[i];//������store��洢�����ݷŵ�string buffer����
	}
	//cout << "\t\t��һ�ε��ļ�����Ϊ:\t" << buffer << endl << endl;
}

//��ǩ�˵ĺ��������������ļ��������չʾ�ļ�����
void Ecdsa::printHash384Verify() {

	char* filename = (char*)malloc(sizeof(char) * 10);//filename��Ϊ�˴洢��ȡ�ļ�������
	cout << "\t\t������Ҫ��ǩ���ļ���: ";
	cin >> filename;
	cout << endl;
	FILE* fptr = fopen(filename, "r");//�����ļ�ָ��ָ��Ҫ�򿪵��ļ�
	int c;
	//string filename("input.txt");
	vector<char> store;//�����洢�ļ�����
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

	while (c = fgetc(fptr), c != EOF) {//whileѭ�������ļ��������һ���ַ�һ���ַ��Ķ�ȡ���洢������store����
		store.push_back(c);
	}
	fclose(fptr);

	for (int i = 0; i < store.size(); i++) {
		buffer1 += store[i];//������store��洢�����ݷŵ�string buffer����
	}
	//cout << "\t\t���յ����ļ�����Ϊ:\t" << buffer1 << endl << endl;
}

//�˺������ļ����ݽ���SHA512��ϣ����չʾ��ϣֵ���ļ�����Ϊconst char* ���͵�����
int Ecdsa::sign384(unsigned char** der, unsigned int* dlen, const char* message, unsigned int len)
{
	ECDSA_SIG* signature;//�ṹ��ECDSA_SIG��ͷ�ļ�ec.h���Դ��Ķ���Ľṹ�壬����������ṹ���ָ��
	unsigned int der_len;
	unsigned char* der_copy;

	string dst = sha512(message, len);
	cout << "\t\t�ļ���SHA512��ϣֵΪ:\t" << dst << endl << endl;
	const unsigned char* dst1 = (const unsigned char*)dst.c_str();
	//this->sha256(digest, message, len);//���յ�digest��������һ��������Ǹ���ϣ������
	signature = ECDSA_do_sign(dst1, sizeof(dst1), this->key);//��ʱdigest���������ˣ���һ�����룬Ȼ���������ǩ������룬����ǩ���������ص���һ���Ѿ������˵Ľṹ��ָ��

	//cout << "r: " << BN_bn2hex(signature->r) << endl;//������ʵ��ǩ���γɵ����꣨r,s),�������ȥ��ע�ͣ����д���ԭ����signature->r�����ﲻ�Ϸ��������������signatureָ��Ľṹ��ECDSA_SIG��typedef��û�����ݣ��ṹ��ECDSA_SIG
	// ֻ�Ǳ�forward declare�ˣ���������Щ���ݲ�û�����������Ա���������signature���ָ��ָ��һ���������ṹ�壬ԭ��Ӧ���������õ�openssl�汾��������������һЩ���õĺ���Բ������صĽṹ�壬���ڰ�ȫ����
	// �������꣨r,s)�������׼��ǩ����ʽ�����׼��ǩ������һ������㣬�����ǵ������ַ���
	//cout << "s: " << BN_bn2hex(signature->s) << endl;

	*dlen = ECDSA_size(this->key);
	*der = (unsigned char*)calloc(*dlen, sizeof(unsigned char));
	der_copy = *der;
	i2d_ECDSA_SIG(signature, &der_copy);

	cout << "\t\t�Թ�ϣֵ��ǩ��Ϊ:\t" << signature << endl << endl;//ͬ�ϣ�����һ�¿�������
	ECDSA_SIG_free(signature);//ǩ�����ͷŵ��ˣ�����ǩ���������

	return 0;
}
//��֤ǩ���ĺ�����������Ҫ�Ĳ�����sign384�ǳ����ƣ����Ҷ�����Ҫ��һ����������Ϊconst char*���ļ����ݺ�����ļ����ݵ��ַ�������
int Ecdsa::verify384(const unsigned char* der, unsigned int der_len, const char* message, unsigned int len)
{
	const unsigned char* der_copy;
	ECDSA_SIG* signature;
	//unsigned char digest[32];//��������������洢��ϣֵ�ģ�����һ��������Ǹ���ϣ��������������Ǵ������digest��
	int res;
	der_copy = der;

	signature = d2i_ECDSA_SIG(NULL, &der_copy, der_len);//�����õ�ǩ���ĺ�����sign�ﲻһ��������ԭ��û����ϸ��������openssl���н���

	//this->sha256(message, len);//�ٴν��й�ϣ����һ������
	string dst = sha512(message, len);
	cout << "\t\t�ٴβ鿴�ļ���SHA512��ϣֵΪ:\t" << dst << endl << endl;
	const unsigned char* dst1 = (const unsigned char*)dst.c_str();
	/** 1:verified. 2:not verified. 3:library error. **/

	res = ECDSA_do_verify(dst1, sizeof(dst1), signature, this->p_key);//��ʱdigest���������ˣ���һ�����룬Ȼ���������ǩ������룬����ǩ���������ص���һ���Ѿ������˵Ľṹ��ָ��

	cout << "\t\t�ٴβ鿴�Թ�ϣֵ��ǩ��Ϊ:\t" << signature << endl << endl;//ͬ�ϣ�����һ�¿�������

	return res;//�����1��ǩ����ǩ�ɹ���������������֣���ʧ��
}
//��������Ǵ�ӡ����Կ��˽Կ
int Ecdsa::print384()
{
	cout << "\t\t˽ԿΪ�� (" << this->priv_b_length << "bytes) #:" << endl;
	for (int t = 0; t < this->priv_b_length; t++)
	{
		cout << hex << setw(2) << setfill('0') << (unsigned int)this->priv_b[t];
	}
	cout << endl << endl;
	cout << dec << "\t\tδѹ���Ĺ�ԿΪ�� (" << this->pub_uncom_length << "bytes) #:" << endl;
	for (int t = 0; t < this->pub_uncom_length; t++)
	{
		cout << hex << setw(2) << setfill('0') << (unsigned int)this->pub_uncom[t];
	}
	cout << endl << endl;
	cout << dec << "\t\tѹ����Ĺ�ԿΪ�� (" << this->pub_com_length << "bytes) #:" << endl << endl;
	for (int t = 0; t < this->pub_com_length; t++)
	{
		cout << hex << setw(2) << setfill('0') << (unsigned int)this->pub_com[t];
	}
	cout << endl << endl;;
	return 0;
}
//����˽Կ
int Ecdsa::setPriv384(const unsigned char* priv_b)
{
	this->priv_b = priv_b;
	this->priv_b_length = 64;//!
	return 0;
}
//���ɹ�Կ
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

//SHA512�������й�ϣ�����
string Ecdsa::sha512(const char* message, unsigned int len) {

	unsigned char digest1[SHA512_DIGEST_LENGTH];//�յ�char���飬����װSHA512�Ĺ�ϣֵ
	SHA512_CTX ctx;//openSSL�ﶨ���һ��SHA512�ṹ��
	SHA512_Init(&ctx);//�˺�����ʼ������ṹ��
	SHA512_Update(&ctx, message, len);//�˺����ǽ��й�ϣ����ĺ��������Ա���������
	SHA512_Final(digest1, &ctx);//�����յĹ�ϣ����洢��digest1����������ʱ�Ĺ�ϣֵ��һ�����룬���Ǳ���ת����16���Ƹ�ʽ
	stringstream ss;
	//for ѭ����ʵ����䣬���ҽ�digest1���������ת����16���Ƹ�ʽ��setw()��setfill()�ֱ�������Ⱥ��������
	for (int i = 0; i < SHA512_DIGEST_LENGTH; i++)
	{
		ss << hex << setw(2) << setfill('0') << (int)digest1[i];
	}

	string finalHash = ss.str();//�����ù�ϣֵת����string��ʽ
	return finalHash;
}
