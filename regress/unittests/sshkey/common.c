/* 	$OpenBSD: common.c,v 1.5 2021/12/14 21:25:27 deraadt Exp $ */
/*
 * Helpers for key API tests
 *
 * Placed in the public domain
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef WITH_OPENSSL
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/objects.h>
#if WITH_OPENSSL_V3
# include <openssl/core_names.h>
# include <openssl/evp.h>
#else
#ifdef OPENSSL_HAS_ECC
# include <openssl/ec.h>
#endif /* OPENSSL_HAS_ECC */
#endif /* WITH_OPENSSL_V3 */
#endif /* WITH_OPENSSL */

#include "openbsd-compat/openssl-compat.h"

#include "../test_helper/test_helper.h"

#include "ssherr.h"
#include "authfile.h"
#include "sshkey.h"
#include "sshbuf.h"

#include "common.h"

struct sshbuf *
load_file(const char *name)
{
	struct sshbuf *ret = NULL;

	ASSERT_INT_EQ(sshbuf_load_file(test_data_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, NULL);
	return ret;
}

struct sshbuf *
load_text_file(const char *name)
{
	struct sshbuf *ret = load_file(name);
	const u_char *p;

	/* Trim whitespace at EOL */
	for (p = sshbuf_ptr(ret); sshbuf_len(ret) > 0;) {
		if (p[sshbuf_len(ret) - 1] == '\r' ||
		    p[sshbuf_len(ret) - 1] == '\t' ||
		    p[sshbuf_len(ret) - 1] == ' ' ||
		    p[sshbuf_len(ret) - 1] == '\n')
			ASSERT_INT_EQ(sshbuf_consume_end(ret, 1), 0);
		else
			break;
	}
	/* \0 terminate */
	ASSERT_INT_EQ(sshbuf_put_u8(ret, 0), 0);
	return ret;
}

#ifdef WITH_OPENSSL
BIGNUM *
load_bignum(const char *name)
{
	BIGNUM *ret = NULL;
	struct sshbuf *buf;

	buf = load_text_file(name);
	ASSERT_INT_NE(BN_hex2bn(&ret, (const char *)sshbuf_ptr(buf)), 0);
	sshbuf_free(buf);
	return ret;
}

BIGNUM *
rsa_n(struct sshkey *k)
{
#if WITH_OPENSSL_V3
	BIGNUM *n = NULL;

	ASSERT_INT_EQ(EVP_PKEY_get_bn_param(k->pkey, OSSL_PKEY_PARAM_RSA_N, &n), 1);
	return n;
#else
	ASSERT_PTR_NE(k, NULL);
	ASSERT_PTR_NE(k->rsa, NULL);
	return BN_dup(RSA_get0_n(k->rsa));
#endif /* WITH_OPENSSL_V3 */
}

BIGNUM *
rsa_e(struct sshkey *k)
{
#if WITH_OPENSSL_V3
	BIGNUM *e = NULL;

	ASSERT_INT_EQ(EVP_PKEY_get_bn_param(k->pkey, OSSL_PKEY_PARAM_RSA_E, &e), 1);
	return e;
#else
	ASSERT_PTR_NE(k, NULL);
	ASSERT_PTR_NE(k->rsa, NULL);
	return BN_dup(RSA_get0_e(k->rsa));
#endif /* WITH_OPENSSL_V3 */
}

BIGNUM *
rsa_p(struct sshkey *k)
{
#if WITH_OPENSSL_V3
	BIGNUM *p = NULL;
	EVP_PKEY_get_bn_param(k->pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, &p);
	return p;
#else
	const BIGNUM *p = NULL;

	ASSERT_PTR_NE(k, NULL);
	ASSERT_PTR_NE(k->rsa, NULL);
	RSA_get0_factors(k->rsa, &p, NULL);
	return BN_dup(p);
#endif /* WITH_OPENSSL_V3 */
}

BIGNUM *
rsa_q(struct sshkey *k)
{
#if WITH_OPENSSL_V3
	BIGNUM *q = NULL;
	EVP_PKEY_get_bn_param(k->pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, &q);
	return q;
#else
	const BIGNUM *q = NULL;

	ASSERT_PTR_NE(k, NULL);
	ASSERT_PTR_NE(k->rsa, NULL);
	RSA_get0_factors(k->rsa, NULL, &q);
	return BN_dup(q);
#endif /* WITH_OPENSSL_V3 */
}

BIGNUM *
dsa_g(struct sshkey *k)
{
#if WITH_OPENSSL_V3
	BIGNUM *g = NULL;

	ASSERT_INT_EQ(EVP_PKEY_get_bn_param(k->pkey, OSSL_PKEY_PARAM_FFC_G, &g), 1);
	return g;
#else
	const BIGNUM *g = NULL;

	ASSERT_PTR_NE(k, NULL);
	ASSERT_PTR_NE(k->dsa, NULL);
	DSA_get0_pqg(k->dsa, NULL, NULL, &g);
	return BN_dup(g);
#endif /* WITH_OPENSSL_V3 */
}

BIGNUM *
dsa_pub_key(struct sshkey *k)
{
#if WITH_OPENSSL_V3
	BIGNUM *pub_key = NULL;

	ASSERT_INT_EQ(EVP_PKEY_get_bn_param(k->pkey, OSSL_PKEY_PARAM_PUB_KEY, &pub_key), 1);
	return pub_key;
#else
	const BIGNUM *pub_key = NULL;

	ASSERT_PTR_NE(k, NULL);
	ASSERT_PTR_NE(k->dsa, NULL);
	DSA_get0_key(k->dsa, &pub_key, NULL);
	return BN_dup(pub_key);
#endif /* WITH_OPENSSL_V3 */
}

BIGNUM *
dsa_priv_key(struct sshkey *k)
{
#if WITH_OPENSSL_V3
	BIGNUM *priv_key = NULL;
	EVP_PKEY_get_bn_param(k->pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv_key);
	return priv_key;
#else
	const BIGNUM *priv_key = NULL;

	ASSERT_PTR_NE(k, NULL);
	ASSERT_PTR_NE(k->dsa, NULL);
	DSA_get0_key(k->dsa, NULL, &priv_key);
	return BN_dup(priv_key);
#endif /* WITH_OPENSSL_V3 */
}

#ifdef OPENSSL_HAS_ECC

BIGNUM *
ec_pub_key(struct sshkey *k)
{
#if WITH_OPENSSL_V3
	BIGNUM *pub_key = NULL;
	size_t size = 0;
	unsigned char *p = NULL;

	ASSERT_INT_EQ(EVP_PKEY_get_octet_string_param(k->pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0, &size), 1);
	p = malloc(size);
	ASSERT_PTR_NE(p, NULL);
	ASSERT_INT_EQ(EVP_PKEY_get_octet_string_param(k->pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, p, size, NULL), 1);
	pub_key = BN_bin2bn(p, size, NULL);
	ASSERT_PTR_NE(pub_key, NULL);
	free(p);
	return pub_key;
#else
	ASSERT_PTR_NE(k->ecdsa, NULL);
	return EC_POINT_point2bn(EC_KEY_get0_group(k->ecdsa), EC_KEY_get0_public_key(k->ecdsa),
                             POINT_CONVERSION_UNCOMPRESSED, NULL, NULL);
#endif /* WITH_OPENSSL_V3 */
}

BIGNUM *
ec_priv_key(struct sshkey *k)
{
#if WITH_OPENSSL_V3
	BIGNUM *priv_key = NULL;
	EVP_PKEY_get_bn_param(k->pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv_key);
	return priv_key;
#else
	ASSERT_PTR_NE(k->ecdsa, NULL);
	return BN_dup(EC_KEY_get0_private_key(k->ecdsa));
#endif /* WITH_OPENSSL_V3 */
}

#endif /* OPENSSL_HAS_ECC */
#endif /* WITH_OPENSSL */
