/*#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<openssl/rsa.h>
#include<openssl/pem.h>
#include<openssl/err.h>


char* my_encrypt(char* str, char* path_key);
char* my_decrypt(char* str, char* path_key);
#define PUBLICKEY "public.pem"
#define OPENSSLKEY "private.pem"
#define BUFFSIZE 1024

int main(void) {

	FILE* hash = fopen("hashed_result.txt", "r");

	char hashedstring[256];
	int useless = 0;
	while (fgets(hashedstring, 256, hash) != NULL) {
		useless++;
	}
	//printf("%s\n", hashedstring);


	char* source = (char*)malloc(sizeof(char) * 257);
	strcpy(source, hashedstring);

	//printf("%s\n", source);

	char* ptr_en, * ptr_de;
	printf("source is :%s\n", source);
	ptr_en = my_encrypt(source, PUBLICKEY);
	printf("after encrypt:%s\n", ptr_en);
	ptr_de = my_decrypt(ptr_en, OPENSSLKEY);
	printf("after decrypt:%s\n", ptr_de);

	if (ptr_en != NULL) {
		free(ptr_en);
	}
	if (ptr_de != NULL) {
		free(ptr_de);
	}

	return 0;
}
char* my_encrypt(char* str, char* path_key) {
	char* p_en;
	RSA* p_rsa;
	FILE* file;
	int flen, rsa_len;
	if ((file = fopen(path_key, "r")) == NULL) {
		perror("open key file error");
		return NULL;

	}
	//if ((p_rsa = PEM_read_RSA_PUBKEY(file, NULL, NULL, NULL)) == NULL) {
	if ((p_rsa = PEM_read_RSAPublicKey(file, NULL, NULL, NULL)) == NULL) {   //换成这句死活通不过，无论是否将公钥分离源文件
		ERR_print_errors_fp(stdout);
		return NULL;
	}
	flen = strlen(str);
	rsa_len = RSA_size(p_rsa);
	p_en = (unsigned char*)malloc(rsa_len + 1);
	memset(p_en, 0, rsa_len + 1);
	if (RSA_public_encrypt(rsa_len, (unsigned char*)str, (unsigned char*)p_en, p_rsa, RSA_NO_PADDING) < 0) {
		return NULL;
	}
	RSA_free(p_rsa);
	fclose(file);
	return p_en;
}
char* my_decrypt(char* str, char* path_key) {
	char* p_de;
	RSA* p_rsa;
	FILE* file;
	int rsa_len;
	if ((file = fopen(path_key, "r")) == NULL) {
		perror("open key file error");
		return NULL;
	}
	if ((p_rsa = PEM_read_RSAPrivateKey(file, NULL, NULL, NULL)) == NULL) {
		ERR_print_errors_fp(stdout);
		return NULL;
	}
	rsa_len = RSA_size(p_rsa);
	p_de = (unsigned char*)malloc(rsa_len + 1);
	memset(p_de, 0, rsa_len + 1);
	if (RSA_private_decrypt(rsa_len, (unsigned char*)str, (unsigned char*)p_de, p_rsa, RSA_NO_PADDING) < 0) {
		return NULL;
	}
	RSA_free(p_rsa);
	fclose(file);
	return p_de;
}*/