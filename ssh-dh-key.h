#ifndef SSH_DH_KEY_H
#define SSH_DH_KEY_H

#include "includes.h"

#ifdef WITH_OPENSSL

#if OPENSSL_VERSION_NUMBER >= 0x3000000L

#include <openssl/evp.h>

struct ssh_dh_key
{
	EVP_PKEY *params;
	EVP_PKEY *pkey;
};

typedef struct ssh_dh_key SSH_DH_KEY;

#else

#include <openssl/dh.h>

typedef DH SSH_DH_KEY;

#endif /* OPENSSL_VERSION_NUMBER >= 0x3000000L */

#endif /* WITH_OPENSSL */

#endif /* SSH_DH_KEY_H */
