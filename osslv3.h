#ifndef OSSLV3_H
#define OSSLV3_H

#include "config.h"

#if WITH_OPENSSL_V3

#include <stddef.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>

/* For crypto_sign_ed25519_PUBLICKEYBYTES, crypto_sign_ed25519_SECRETKEYBYTES */
#include "crypto_api.h"

#ifndef ED25519_SK_SZ
#define	ED25519_SK_SZ	crypto_sign_ed25519_SECRETKEYBYTES
#endif /* ED25519_SK_SZ */
#ifndef ED25519_PK_SZ
#define	ED25519_PK_SZ	crypto_sign_ed25519_PUBLICKEYBYTES
#endif /* ED25519_PK_SZ */

/* From PKCS #1 RSAPrivateKey */
struct ssh_rsa_key_params {
	/* public key */
	BIGNUM *n; /* modulus */
	BIGNUM *e; /* publicExponent */
	/* private key */
	BIGNUM *d; /* privateExponent */
	BIGNUM *p; /* prime1 */
	BIGNUM *q; /* prime2 */
	BIGNUM *iqmp; /* coefficient ((inverse of q) mod p)*/
};

struct ssh_rsa_exponents {
	BIGNUM *dmp1; /* exponent1 (d mod (p-1)) */
	BIGNUM *dmq1; /* exponent2 (d mod (q-1)) */
};

struct ssh_dsa_key_params {
	BIGNUM *p;
	BIGNUM *g;
	BIGNUM *q;
	BIGNUM *pub_key;
	BIGNUM *priv_key;
};

struct ssh_ec_key_params {
	int curve_nid;
	unsigned char *pub;
	size_t pub_len;
	BIGNUM *exponent;
};

struct ssh_ed25519_key_params {
	/* format:
	offset size description
	0      32   secret key (optional)
	32     32   public key
	*/
	u_char sk[ED25519_SK_SZ];
};

int	ssh_get_rsa_key_params(EVP_PKEY *pkey, struct ssh_rsa_key_params *kp, int private);
int	ssh_rsa_new_pkey(const struct ssh_rsa_key_params *kp, EVP_PKEY **pkeyp);
void	ssh_rsa_key_params_deinit(struct ssh_rsa_key_params *kp);

int	ssh_get_dsa_key_params(EVP_PKEY *pkey, struct ssh_dsa_key_params *dsa_param, int private);
int	ssh_dsa_new_pkey(const struct ssh_dsa_key_params *kp, EVP_PKEY **pkeyp);
void	ssh_dsa_key_params_deinit(struct ssh_dsa_key_params *kp);

int	ssh_get_ec_key_params(EVP_PKEY *pkey, struct ssh_ec_key_params *kp, int private);
int	ssh_ec_new_pkey(const struct ssh_ec_key_params *kp, EVP_PKEY **pkeyp);
void	ssh_ec_key_params_deinit(struct ssh_ec_key_params *kp);

int	ssh_get_ed25519_key_params(EVP_PKEY *pkey, struct ssh_ed25519_key_params *kp, int private);
int	ssh_ed25519_new_pkey(const struct ssh_ed25519_key_params *kp, int priv, EVP_PKEY **pkeyp);
void	ssh_ed25519_key_params_deinit(struct ssh_ed25519_key_params *kp);

#endif /* WITH_OPENSSL_V3 */
#endif /* OSSLV3_H */
