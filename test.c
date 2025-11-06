#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <openssl/ssl.h>


int main()
{
	const char* ptr = OpenSSL_version(OPENSSL_VERSION);
	printf("OpenSSL: %s\n", ptr);
	return 0;
}

