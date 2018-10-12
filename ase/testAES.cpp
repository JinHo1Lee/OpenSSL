#include <iostream>
#include <cstring>
#include <openssl/evp.h>

// "1234" 문자열로 키 생성.
//
// 아래 명령 결과와 같은 키 생성됨.
// openssl enc -aes-128-cbc -k 1234 -md md5 -nosalt -p < /dev/null
//

using namespace std;
const unsigned char *gKey= (unsigned char*)"1234";

const EVP_CIPHER *getCipher()
{
	return EVP_aes_256_cbc();
}


int32_t encryptAES(unsigned char *plain, unsigned char *encrypt, int size)
{
    int cipherLen = 0;
    unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];

	memset(iv, 0x00, sizeof(iv));

    memset(key, 0, EVP_MAX_KEY_LENGTH);
    int key_bytes = EVP_BytesToKey(getCipher(), EVP_md5(), NULL, gKey, 4, 1, key, iv);
    BIO_dump_fp(stdout, (const char *)key, key_bytes);

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    EVP_EncryptInit_ex(&ctx, getCipher(), NULL, (unsigned char*)key, iv);
    int outl, outl2;
    EVP_EncryptUpdate(&ctx, encrypt, &outl, plain, size);
    EVP_EncryptFinal_ex(&ctx, encrypt + outl, &outl2);

    cipherLen = outl + outl2;

    return cipherLen;
}

int32_t decryptAES(unsigned char *encrypt, unsigned char *decrypt, int size)
{
    int decryptLen = 0;
    int len = 0;
    unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];

    memset(key, 0, EVP_MAX_KEY_LENGTH);
	memset(iv, 0x00, sizeof(iv));

    int key_bytes = EVP_BytesToKey(getCipher(), EVP_md5(), NULL, gKey, 4, 1, key, iv);
    BIO_dump_fp(stdout, (const char *)key, key_bytes);

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    EVP_DecryptInit_ex(&ctx, getCipher(), NULL, (unsigned char*)key, iv);
    EVP_DecryptUpdate(&ctx, decrypt, &len, encrypt, size);
    decryptLen = len;
    EVP_DecryptFinal_ex(&ctx, decrypt+len, &len);
    decryptLen += len;

    return decryptLen;
}

int main (int argc, char **argv)
{
	unsigned char plaintext[128];
	int plaintext_len;
	unsigned char encrypttext[128];
	int encrypttext_len;
	unsigned char decrypttext[128];
	int decrypttext_len;

	memset(plaintext, 0x00, sizeof(plaintext));

    strcpy((char*)plaintext, "hello");
    plaintext_len = strlen((char*)plaintext);

	cout<<"=========== Encrypt ==========="<<endl;
	encrypttext_len = encryptAES(plaintext, encrypttext, strlen((char*)plaintext));
	BIO_dump_fp(stdout, (const char*)encrypttext, encrypttext_len);

	cout<<"=========== Decrypt ==========="<<endl;
	decrypttext_len = decryptAES(encrypttext, decrypttext, encrypttext_len);
	BIO_dump_fp(stdout, (const char*)decrypttext, decrypttext_len);

	return 0;
}
