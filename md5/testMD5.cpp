//#include "md5.h"
#include <openssl/md5.h> // for generate md5 hash
#include <cstring>
#include <string>
#include <iostream>
#include <cstdio>
#include <stdint.h>

using namespace std;

const char * hexmd5_of_buffer( const char * buf, size_t len )
{
    static unsigned char digest[16];
    static char ret[33] = { 0, };

    MD5_CTX context;
    MD5_Init(&context);
    MD5_Update(&context, (unsigned char*)buf, len);
    MD5_Final(digest, &context);

	for (int i=0;i<16;++i)
	{
		sprintf(ret + i*2, "%02x", digest[i]);
	}

    printf("res of md5(%s) : %s\n", buf, ret);

	return ret;
}

void genMD5Hash(char *str)
{
	unsigned int nPasswdSizeBase64;
    char * pEncodedPasswd = NULL;
    char acTempConvert[100];

    strcpy(acTempConvert, hexmd5_of_buffer(str, strlen(str)));

    //convert hex md5 to binary data
    int32_t iUnHexStrLen = strlen(acTempConvert) /2;
    char *pcEncryptUnHexContent = new char[iUnHexStrLen+1];
    int n;

    memset(pcEncryptUnHexContent, 0x00, iUnHexStrLen+ 1);

    for(int i =0; i < iUnHexStrLen; i ++)
    {
        sscanf(acTempConvert+2*i, "%2X", &n);
        pcEncryptUnHexContent[i] = (char)n;
    }
}

int main(int argc, char *argv[])
{
	char acTempConvert[50];
	char str[10];
	char tmpEnc[100];
	char tmpStr[100];


	strcpy (str, "hello world");
	strcpy (tmpEnc, hexmd5_of_buffer(str, strlen(str)));

    return 0;
}

