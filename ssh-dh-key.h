#ifndef SSH_DH_KEY_H
#define SSH_DH_KEY_H

#include "includes.h"

#ifdef WITH_OPENSSL
#if WITH_OPENSSL_V3

#include <openssl/evp.h>

struct ssh_dh_key {
	EVP_PKEY *params;
	EVP_PKEY *pkey;
};

typedef struct ssh_dh_key SSH_DH_KEY;

#else

#include <openssl/dh.h>

typedef DH SSH_DH_KEY;

#endif /* WITH_OPENSSL_V3 */
#endif /* WITH_OPENSSL */

#endif /* SSH_DH_KEY_H */
