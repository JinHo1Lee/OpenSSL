#include <iostream>
#include <cstring>
#include <string>
#include <cstdio>
#include <fstream>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

using namespace std;

int padding = RSA_PKCS1_PADDING;
char m_PublicFile[100] = "./public.pem";
char m_PrivateFile[100] = "./private.pem";

RSA *createRSAFilename (char *filename, int iPublic)
{
	FILE *fp = fopen(filename, "rb");
	RSA *rsa;
	if (fp != NULL)
	{
		rsa = RSA_new();
		if (iPublic)
		{
			rsa = PEM_read_RSA_PUBKEY(fp, &rsa, NULL, NULL);
		}
		else
		{
			rsa = PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL);
		}
	}
	else
	{
		return NULL;
	}

	return rsa;
}

int public_encrypt(unsigned char *plain, unsigned char *encrypted)
{
	RSA *rsa = createRSAFilename(m_PublicFile, 1);
    int result = RSA_public_encrypt(strlen((char*)plain), plain, encrypted, rsa, padding);
    return result;
}

int public_decrypt(unsigned char *encrypted, unsigned char *decrypted)
{
	RSA *rsa = createRSAFilename(m_PublicFile, 1);
    int result = RSA_public_decrypt(RSA_size(rsa), encrypted, decrypted, rsa, padding);
    return result;
}

int private_encrypt (unsigned char *plain, unsigned char *encrypted)
{
	RSA *rsa = createRSAFilename(m_PrivateFile, 0);
    int  result = RSA_private_encrypt(strlen((char*)plain), plain, encrypted, rsa, padding);
    return result;
}

int private_decrypt(unsigned char *encrypted, unsigned char *decrypted)
{
	RSA *rsa = createRSAFilename(m_PrivateFile, 0);
    int  result = RSA_private_decrypt(RSA_size(rsa), encrypted, decrypted, rsa, padding);
    return result;
}

void printLastError(char *msg)
{
    char err[130];
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n",msg, err);
}

int main (int argc, char** argv)
{
	unsigned char plain[256];
	unsigned char encrypt[256];
	unsigned char decrypt[256];

	memset(plain, 0x00, sizeof(plain));
	memset(encrypt, 0x00, sizeof(encrypt));
	memset(decrypt, 0x00, sizeof(decrypt));

	strcpy((char*)plain, "hello world");

	int encrypted_length= private_encrypt(plain, encrypt);
	if(encrypted_length == -1)
	{
		printLastError((char*)"Public Encrypt failed ");
		exit(0);
	}
	printf("Encrypted length = %d\n",encrypted_length);

	int decrypted_length = public_decrypt(encrypt, decrypt);
	if(decrypted_length == -1)
	{
		printLastError((char*)"Private Decrypt failed ");
		exit(0);
	}

	printf("Decrypted Length = %d\n",decrypted_length);
	printf("Decrypted Text = %s\n",decrypt);

	return 0;
}
