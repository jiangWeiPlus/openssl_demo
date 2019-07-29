#include <cstdio>
#include <openssl/rsa.h>
#include <iostream>
#include <string>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/err.h>


using namespace std;


const char *OPENSSLKEY = "/root/test.key";
const char *PUBLICKEY = "/root/test_pub.key";

unsigned char *encrypt(const char *str,const int len, const char *pub_key)
{

	FILE* p_keyfile = fopen(pub_key, "r");
	if (p_keyfile == NULL)
	{
		perror("file ptr is null.");
		return NULL;
	}
	RSA* p_rsa = PEM_read_RSA_PUBKEY(p_keyfile, NULL, NULL, NULL);
	int rsa_len = RSA_size(p_rsa);
	unsigned char* p_en = (unsigned char*)malloc(rsa_len + 1);
	memset(p_en, 0, rsa_len + 1);
	RSA_public_encrypt(rsa_len, (unsigned char*)str, (unsigned char*)p_en, p_rsa, RSA_NO_PADDING);
	RSA_free(p_rsa);
	fclose(p_keyfile);
	return p_en;
}

unsigned char *decrypt(const unsigned char *str, const char *pri_key)
{
	FILE *p_keyfile = fopen(pri_key, "r");
	if (p_keyfile == NULL)
	{
		perror("file ptr is null.");
		return NULL;
	}
	RSA* p_rsa = PEM_read_RSAPrivateKey(p_keyfile, NULL, NULL, NULL);
	int rsa_len = RSA_size(p_rsa);
	unsigned char* p_de = (unsigned char*)malloc(rsa_len + 1);
	memset(p_de, 0, rsa_len + 1);
	RSA_private_decrypt(rsa_len, (unsigned char*)str, (unsigned char*)p_de, p_rsa, RSA_NO_PADDING);
	RSA_free(p_rsa);
	fclose(p_keyfile);
	return p_de;

}


int main()
{

	unsigned char str_sign[10] = "123456";
	//unsigned char* en_str = encrypt(str, strlen(str), PUBLICKEY);
	//cout << en_str << endl;


	unsigned char signret[200];
	unsigned int signlen;
	FILE* p_prikey = fopen(OPENSSLKEY, "r");
	RSA* p_prirsa = PEM_read_RSAPrivateKey(p_prikey, NULL, NULL, NULL);
	cout << RSA_sign(NID_sha256, str_sign, 10, signret, &signlen, p_prirsa) << endl;


	unsigned char str_verify[10] = "123456";
	FILE* p_pubkey = fopen(PUBLICKEY, "r");
	RSA* p_pubrsa = PEM_read_RSA_PUBKEY(p_pubkey, NULL, NULL, NULL);
	//如果签名正确返回 1, 签名错误返回 0, 内部发生错误则返回-1
	cout << RSA_verify(NID_sha256, str_verify, 10, signret, signlen, p_pubrsa) << endl;

	//unsigned char* de_str = decrypt(en_str, OPENSSLKEY);
	//cout << de_str << endl;

    return 0;
}