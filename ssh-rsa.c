/* $OpenBSD: ssh-rsa.c,v 1.67 2018/07/03 11:39:54 djm Exp $ */
/*
 * Copyright (c) 2000, 2003 Markus Friedl <markus@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "includes.h"

#ifdef WITH_OPENSSL

#include <sys/types.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#if OPENSSL_VERSION_NUMBER >= 0x3000000L
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#endif

#include <stdarg.h>
#include <string.h>

#include "sshbuf.h"
#include "compat.h"
#include "ssherr.h"
#define SSHKEY_INTERNAL
#include "sshkey.h"
#include "digest.h"
#include "log.h"

#include "openbsd-compat/openssl-compat.h"

struct ssh_rsa_exponents
{
	BIGNUM *dmp1; /* exponent1 (d mod (p-1)) */
	BIGNUM *dmq1; /* exponent2 (d mod (q-1)) */
};

static const char *
rsa_hash_alg_ident(int hash_alg)
{
	switch (hash_alg) {
	case SSH_DIGEST_SHA1:
		return "ssh-rsa";
	case SSH_DIGEST_SHA256:
		return "rsa-sha2-256";
	case SSH_DIGEST_SHA512:
		return "rsa-sha2-512";
	}
	return NULL;
}

/*
 * Returns the hash algorithm ID for a given algorithm identifier as used
 * inside the signature blob,
 */
static int
rsa_hash_id_from_ident(const char *ident)
{
	if (strcmp(ident, "ssh-rsa") == 0)
		return SSH_DIGEST_SHA1;
	if (strcmp(ident, "rsa-sha2-256") == 0)
		return SSH_DIGEST_SHA256;
	if (strcmp(ident, "rsa-sha2-512") == 0)
		return SSH_DIGEST_SHA512;
	return -1;
}

/*
 * Return the hash algorithm ID for the specified key name. This includes
 * all the cases of rsa_hash_id_from_ident() but also the certificate key
 * types.
 */
static int
rsa_hash_id_from_keyname(const char *alg)
{
	int r;

	if ((r = rsa_hash_id_from_ident(alg)) != -1)
		return r;
	if (strcmp(alg, "ssh-rsa-cert-v01@openssh.com") == 0)
		return SSH_DIGEST_SHA1;
	if (strcmp(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
		return SSH_DIGEST_SHA256;
	if (strcmp(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
		return SSH_DIGEST_SHA512;
	return -1;
}

# if OPENSSL_VERSION_NUMBER >= 0x3000000L
static const char *
rsa_digest_name_from_hash_alg(int hash_alg)
{
	const char *mdname;

	switch (hash_alg) {
	case SSH_DIGEST_SHA1:
		mdname = OSSL_DIGEST_NAME_SHA1;
		break;
	case SSH_DIGEST_SHA256:
		mdname = OSSL_DIGEST_NAME_SHA2_256;
		break;
	case SSH_DIGEST_SHA512:
		mdname = OSSL_DIGEST_NAME_SHA2_512;
		break;
	default:
		mdname = NULL;
	}

	return mdname;
}

/* RSASSA-PKCS1-v1_5 (PKCS #1 v2.0 signature) with SHA1 */
int
ssh_rsa_sign(const struct sshkey *key, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen, const char *alg_ident)
{
	size_t len = 0;
	int ret = SSH_ERR_INTERNAL_ERROR;
	int hash_alg;
	const char *mdname = NULL;
	EVP_MD_CTX *ctx = NULL;
	size_t siglen = 0;
	u_char *sig = NULL;
	struct sshbuf *b = NULL;

	if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;

	if (alg_ident == NULL || strlen(alg_ident) == 0)
		hash_alg = SSH_DIGEST_SHA1;
	else
		hash_alg = rsa_hash_id_from_keyname(alg_ident);

	if (key == NULL || key->pkey == NULL || hash_alg == -1 ||
	    EVP_PKEY_get_base_id(key->pkey) != EVP_PKEY_RSA ||
	    sshkey_type_plain(key->type) != KEY_RSA)
		return SSH_ERR_INVALID_ARGUMENT;

	mdname = rsa_digest_name_from_hash_alg(hash_alg);
	if (mdname == NULL) {
		ret = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	if ((ctx = EVP_MD_CTX_new()) == NULL) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	if (EVP_DigestSignInit_ex(ctx, NULL, mdname, NULL, NULL, key->pkey, NULL) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	if (EVP_DigestSign(ctx, NULL, &siglen, NULL, 0) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	if ((sig = malloc(siglen)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if (EVP_DigestSign(ctx, sig, &siglen, data, datalen) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	/* encode signature */
	if ((b = sshbuf_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((ret = sshbuf_put_cstring(b, rsa_hash_alg_ident(hash_alg))) != 0 ||
	    (ret = sshbuf_put_string(b, sig, siglen)) != 0)
		goto out;
	len = sshbuf_len(b);
	if (sigp != NULL) {
		if ((*sigp = malloc(len)) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	if (lenp != NULL)
		*lenp = len;
	ret = 0;
 out:
	EVP_MD_CTX_free(ctx);
	freezero(sig, siglen);
	sshbuf_free(b);
	return ret;
}

int
ssh_rsa_verify(const struct sshkey *key,
    const u_char *sig, size_t siglen, const u_char *data, size_t datalen,
    const char *alg)
{
	char *sigtype = NULL;
	int hash_alg, want_alg, ret = SSH_ERR_INTERNAL_ERROR;
	size_t len = 0, diff, modlen;
	struct sshbuf *b = NULL;
	u_char *osigblob, *sigblob = NULL;
	EVP_MD_CTX *ctx = NULL;
	const char *mdname = NULL;

	if (key == NULL || key->pkey == NULL ||
	    EVP_PKEY_get_base_id(key->pkey) != EVP_PKEY_RSA ||
	    sshkey_type_plain(key->type) != KEY_RSA ||
	    sig == NULL || siglen == 0)
		return SSH_ERR_INVALID_ARGUMENT;
	if (EVP_PKEY_get_bits(key->pkey) < SSH_RSA_MINIMUM_MODULUS_SIZE)
		return SSH_ERR_KEY_LENGTH;

	if ((b = sshbuf_from(sig, siglen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (sshbuf_get_cstring(b, &sigtype, NULL) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if ((hash_alg = rsa_hash_id_from_ident(sigtype)) == -1) {
		ret = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}

	mdname = rsa_digest_name_from_hash_alg(hash_alg);
	if (mdname == NULL) {
		ret = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	/*
	 * Allow ssh-rsa-cert-v01 certs to generate SHA2 signatures for
	 * legacy reasons, but otherwise the signature type should match.
	 */
	if (alg != NULL && strcmp(alg, "ssh-rsa-cert-v01@openssh.com") != 0) {
		if ((want_alg = rsa_hash_id_from_keyname(alg)) == -1) {
			ret = SSH_ERR_INVALID_ARGUMENT;
			goto out;
		}
		if (hash_alg != want_alg) {
			ret = SSH_ERR_SIGNATURE_INVALID;
			goto out;
		}
	}
	if (sshbuf_get_string(b, &sigblob, &len) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}
	/* RSA_verify expects a signature of RSA_size */
	modlen = EVP_PKEY_get_size(key->pkey);
	if (len > modlen) {
		ret = SSH_ERR_KEY_BITS_MISMATCH;
		goto out;
	} else if (len < modlen) {
		diff = modlen - len;
		osigblob = sigblob;
		if ((sigblob = realloc(sigblob, modlen)) == NULL) {
			sigblob = osigblob; /* put it back for clear/free */
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memmove(sigblob + diff, sigblob, len);
		explicit_bzero(sigblob, diff);
		len = modlen;
	}

	if ((ctx = EVP_MD_CTX_new()) == NULL) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	if (EVP_DigestVerifyInit_ex(ctx, NULL, mdname, NULL, NULL, key->pkey, NULL) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	if (EVP_DigestVerify(ctx, sigblob, len, data, datalen) != 1) {
		ret = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}

	ret = 0;

 out:
	EVP_MD_CTX_free(ctx);
	freezero(sigblob, len);
	free(sigtype);
	sshbuf_free(b);
	return ret;
}

static int
push_opt_bn(OSSL_PARAM_BLD *bld, const char *key, const BIGNUM *bn)
{
	if (bn != NULL) {
		if (OSSL_PARAM_BLD_push_BN(bld, key, bn) != 1) {
			return -1;
		}
	}

	return 0;
}

static int
ssh_rsa_new_key_openssl(struct sshkey *key, struct ssh_rsa_key_params *rsa_param, struct ssh_rsa_exponents *rsa_exp)
{
	EVP_PKEY_CTX *ctx = NULL;
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;
	int r = SSH_ERR_LIBCRYPTO_ERROR;

	EVP_PKEY_free(key->pkey);
	key->pkey = NULL;

	if ((ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL)) == NULL) {
		goto out;
	}

	if (EVP_PKEY_fromdata_init(ctx) != 1) {
		goto out;
	}

	if ((bld = OSSL_PARAM_BLD_new()) == NULL) {
		goto out;
	}

	if (push_opt_bn(bld, OSSL_PKEY_PARAM_RSA_N, rsa_param->n) < 0 ||
	    push_opt_bn(bld, OSSL_PKEY_PARAM_RSA_E, rsa_param->e) < 0 ||
	    push_opt_bn(bld, OSSL_PKEY_PARAM_RSA_D, rsa_param->d) < 0 ||
	    push_opt_bn(bld, OSSL_PKEY_PARAM_RSA_FACTOR1, rsa_param->p) < 0 ||
	    push_opt_bn(bld, OSSL_PKEY_PARAM_RSA_FACTOR2, rsa_param->q) < 0 ||
	    push_opt_bn(bld, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, rsa_param->iqmp) < 0 ||
	    push_opt_bn(bld, OSSL_PKEY_PARAM_RSA_EXPONENT1, rsa_exp->dmp1) < 0 ||
	    push_opt_bn(bld, OSSL_PKEY_PARAM_RSA_EXPONENT2, rsa_exp->dmq1) < 0) {
		goto out;
	}

	if ((params = OSSL_PARAM_BLD_to_param(bld)) == NULL) {
		goto out;
	}

	if (EVP_PKEY_fromdata(ctx, &key->pkey, EVP_PKEY_KEYPAIR, params) != 1) {
		goto out;
	}

	r = 0;
out:
	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(bld);
	EVP_PKEY_CTX_free(ctx);
	return r;
}

int
ssh_get_rsa_key_params(const struct sshkey *key, struct ssh_rsa_key_params *rsa_param, int private)
{
	int r = SSH_ERR_LIBCRYPTO_ERROR;

	if (EVP_PKEY_get_bn_param(key->pkey, OSSL_PKEY_PARAM_RSA_N, &rsa_param->n) != 1 ||
	    EVP_PKEY_get_bn_param(key->pkey, OSSL_PKEY_PARAM_RSA_E, &rsa_param->e) != 1) {
		goto out;
	}

	if (private) {
		if (EVP_PKEY_get_bn_param(key->pkey, OSSL_PKEY_PARAM_RSA_D, &rsa_param->d) != 1 ||
		    EVP_PKEY_get_bn_param(key->pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, &rsa_param->p) != 1 ||
		    EVP_PKEY_get_bn_param(key->pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, &rsa_param->q) != 1 ||
		    EVP_PKEY_get_bn_param(key->pkey, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &rsa_param->iqmp) != 1) {
			goto out;
		}
	}

	r = 0;

out:
	return r;
}
# else
static int
rsa_hash_alg_nid(int type)
{
	switch (type) {
	case SSH_DIGEST_SHA1:
		return NID_sha1;
	case SSH_DIGEST_SHA256:
		return NID_sha256;
	case SSH_DIGEST_SHA512:
		return NID_sha512;
	default:
		return -1;
	}
}

static int openssh_RSA_verify(int, u_char *, size_t, u_char *, size_t, RSA *);

int
ssh_rsa_complete_crt_parameters(struct sshkey *key, const BIGNUM *iqmp)
{
	const BIGNUM *rsa_p, *rsa_q, *rsa_d;
	BIGNUM *aux = NULL, *d_consttime = NULL;
	BIGNUM *rsa_dmq1 = NULL, *rsa_dmp1 = NULL, *rsa_iqmp = NULL;
	BN_CTX *ctx = NULL;
	int r;

	if (key == NULL || key->rsa == NULL ||
	    sshkey_type_plain(key->type) != KEY_RSA)
		return SSH_ERR_INVALID_ARGUMENT;

	RSA_get0_key(key->rsa, NULL, NULL, &rsa_d);
	RSA_get0_factors(key->rsa, &rsa_p, &rsa_q);

	if ((ctx = BN_CTX_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((aux = BN_new()) == NULL ||
	    (rsa_dmq1 = BN_new()) == NULL ||
	    (rsa_dmp1 = BN_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((d_consttime = BN_dup(rsa_d)) == NULL ||
	    (rsa_iqmp = BN_dup(iqmp)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	BN_set_flags(aux, BN_FLG_CONSTTIME);
	BN_set_flags(d_consttime, BN_FLG_CONSTTIME);

	if ((BN_sub(aux, rsa_q, BN_value_one()) == 0) ||
	    (BN_mod(rsa_dmq1, d_consttime, aux, ctx) == 0) ||
	    (BN_sub(aux, rsa_p, BN_value_one()) == 0) ||
	    (BN_mod(rsa_dmp1, d_consttime, aux, ctx) == 0)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if (!RSA_set0_crt_params(key->rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	rsa_dmp1 = rsa_dmq1 = rsa_iqmp = NULL; /* transferred */
	/* success */
	r = 0;
 out:
	BN_clear_free(aux);
	BN_clear_free(d_consttime);
	BN_clear_free(rsa_dmp1);
	BN_clear_free(rsa_dmq1);
	BN_clear_free(rsa_iqmp);
	BN_CTX_free(ctx);
	return r;
}

/* RSASSA-PKCS1-v1_5 (PKCS #1 v2.0 signature) with SHA1 */
int
ssh_rsa_sign(const struct sshkey *key, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen, const char *alg_ident)
{
	const BIGNUM *rsa_n;
	u_char digest[SSH_DIGEST_MAX_LENGTH], *sig = NULL;
	size_t slen = 0;
	u_int dlen, len;
	int nid, hash_alg, ret = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *b = NULL;

	if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;

	if (alg_ident == NULL || strlen(alg_ident) == 0)
		hash_alg = SSH_DIGEST_SHA1;
	else
		hash_alg = rsa_hash_id_from_keyname(alg_ident);
	if (key == NULL || key->rsa == NULL || hash_alg == -1 ||
	    sshkey_type_plain(key->type) != KEY_RSA)
		return SSH_ERR_INVALID_ARGUMENT;
	RSA_get0_key(key->rsa, &rsa_n, NULL, NULL);
	if (BN_num_bits(rsa_n) < SSH_RSA_MINIMUM_MODULUS_SIZE)
		return SSH_ERR_KEY_LENGTH;
	slen = RSA_size(key->rsa);
	if (slen <= 0 || slen > SSHBUF_MAX_BIGNUM)
		return SSH_ERR_INVALID_ARGUMENT;

	/* hash the data */
	nid = rsa_hash_alg_nid(hash_alg);
	if ((dlen = ssh_digest_bytes(hash_alg)) == 0)
		return SSH_ERR_INTERNAL_ERROR;
	if ((ret = ssh_digest_memory(hash_alg, data, datalen,
	    digest, sizeof(digest))) != 0)
		goto out;

	if ((sig = malloc(slen)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if (RSA_sign(nid, digest, dlen, sig, &len, key->rsa) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if (len < slen) {
		size_t diff = slen - len;
		memmove(sig + diff, sig, len);
		explicit_bzero(sig, diff);
	} else if (len > slen) {
		ret = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	/* encode signature */
	if ((b = sshbuf_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((ret = sshbuf_put_cstring(b, rsa_hash_alg_ident(hash_alg))) != 0 ||
	    (ret = sshbuf_put_string(b, sig, slen)) != 0)
		goto out;
	len = sshbuf_len(b);
	if (sigp != NULL) {
		if ((*sigp = malloc(len)) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	if (lenp != NULL)
		*lenp = len;
	ret = 0;
 out:
	explicit_bzero(digest, sizeof(digest));
	freezero(sig, slen);
	sshbuf_free(b);
	return ret;
}

int
ssh_rsa_verify(const struct sshkey *key,
    const u_char *sig, size_t siglen, const u_char *data, size_t datalen,
    const char *alg)
{
	const BIGNUM *rsa_n;
	char *sigtype = NULL;
	int hash_alg, want_alg, ret = SSH_ERR_INTERNAL_ERROR;
	size_t len = 0, diff, modlen, dlen;
	struct sshbuf *b = NULL;
	u_char digest[SSH_DIGEST_MAX_LENGTH], *osigblob, *sigblob = NULL;

	if (key == NULL || key->rsa == NULL ||
	    sshkey_type_plain(key->type) != KEY_RSA ||
	    sig == NULL || siglen == 0)
		return SSH_ERR_INVALID_ARGUMENT;
	RSA_get0_key(key->rsa, &rsa_n, NULL, NULL);
	if (BN_num_bits(rsa_n) < SSH_RSA_MINIMUM_MODULUS_SIZE)
		return SSH_ERR_KEY_LENGTH;

	if ((b = sshbuf_from(sig, siglen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (sshbuf_get_cstring(b, &sigtype, NULL) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if ((hash_alg = rsa_hash_id_from_ident(sigtype)) == -1) {
		ret = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}
	/*
	 * Allow ssh-rsa-cert-v01 certs to generate SHA2 signatures for
	 * legacy reasons, but otherwise the signature type should match.
	 */
	if (alg != NULL && strcmp(alg, "ssh-rsa-cert-v01@openssh.com") != 0) {
		if ((want_alg = rsa_hash_id_from_keyname(alg)) == -1) {
			ret = SSH_ERR_INVALID_ARGUMENT;
			goto out;
		}
		if (hash_alg != want_alg) {
			ret = SSH_ERR_SIGNATURE_INVALID;
			goto out;
		}
	}
	if (sshbuf_get_string(b, &sigblob, &len) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}
	/* RSA_verify expects a signature of RSA_size */
	modlen = RSA_size(key->rsa);
	if (len > modlen) {
		ret = SSH_ERR_KEY_BITS_MISMATCH;
		goto out;
	} else if (len < modlen) {
		diff = modlen - len;
		osigblob = sigblob;
		if ((sigblob = realloc(sigblob, modlen)) == NULL) {
			sigblob = osigblob; /* put it back for clear/free */
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memmove(sigblob + diff, sigblob, len);
		explicit_bzero(sigblob, diff);
		len = modlen;
	}
	if ((dlen = ssh_digest_bytes(hash_alg)) == 0) {
		ret = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	if ((ret = ssh_digest_memory(hash_alg, data, datalen,
	    digest, sizeof(digest))) != 0)
		goto out;

	ret = openssh_RSA_verify(hash_alg, digest, dlen, sigblob, len,
	    key->rsa);
 out:
	freezero(sigblob, len);
	free(sigtype);
	sshbuf_free(b);
	explicit_bzero(digest, sizeof(digest));
	return ret;
}

/*
 * See:
 * http://www.rsasecurity.com/rsalabs/pkcs/pkcs-1/
 * ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1.asn
 */

/*
 * id-sha1 OBJECT IDENTIFIER ::= { iso(1) identified-organization(3)
 *	oiw(14) secsig(3) algorithms(2) 26 }
 */
static const u_char id_sha1[] = {
	0x30, 0x21, /* type Sequence, length 0x21 (33) */
	0x30, 0x09, /* type Sequence, length 0x09 */
	0x06, 0x05, /* type OID, length 0x05 */
	0x2b, 0x0e, 0x03, 0x02, 0x1a, /* id-sha1 OID */
	0x05, 0x00, /* NULL */
	0x04, 0x14  /* Octet string, length 0x14 (20), followed by sha1 hash */
};

/*
 * See http://csrc.nist.gov/groups/ST/crypto_apps_infra/csor/algorithms.html
 * id-sha256 OBJECT IDENTIFIER ::= { joint-iso-itu-t(2) country(16) us(840)
 *      organization(1) gov(101) csor(3) nistAlgorithm(4) hashAlgs(2)
 *      id-sha256(1) }
 */
static const u_char id_sha256[] = {
	0x30, 0x31, /* type Sequence, length 0x31 (49) */
	0x30, 0x0d, /* type Sequence, length 0x0d (13) */
	0x06, 0x09, /* type OID, length 0x09 */
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, /* id-sha256 */
	0x05, 0x00, /* NULL */
	0x04, 0x20  /* Octet string, length 0x20 (32), followed by sha256 hash */
};

/*
 * See http://csrc.nist.gov/groups/ST/crypto_apps_infra/csor/algorithms.html
 * id-sha512 OBJECT IDENTIFIER ::= { joint-iso-itu-t(2) country(16) us(840)
 *      organization(1) gov(101) csor(3) nistAlgorithm(4) hashAlgs(2)
 *      id-sha256(3) }
 */
static const u_char id_sha512[] = {
	0x30, 0x51, /* type Sequence, length 0x51 (81) */
	0x30, 0x0d, /* type Sequence, length 0x0d (13) */
	0x06, 0x09, /* type OID, length 0x09 */
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, /* id-sha512 */
	0x05, 0x00, /* NULL */
	0x04, 0x40  /* Octet string, length 0x40 (64), followed by sha512 hash */
};

static int
rsa_hash_alg_oid(int hash_alg, const u_char **oidp, size_t *oidlenp)
{
	switch (hash_alg) {
	case SSH_DIGEST_SHA1:
		*oidp = id_sha1;
		*oidlenp = sizeof(id_sha1);
		break;
	case SSH_DIGEST_SHA256:
		*oidp = id_sha256;
		*oidlenp = sizeof(id_sha256);
		break;
	case SSH_DIGEST_SHA512:
		*oidp = id_sha512;
		*oidlenp = sizeof(id_sha512);
		break;
	default:
		return SSH_ERR_INVALID_ARGUMENT;
	}
	return 0;
}

static int
openssh_RSA_verify(int hash_alg, u_char *hash, size_t hashlen,
    u_char *sigbuf, size_t siglen, RSA *rsa)
{
	size_t rsasize = 0, oidlen = 0, hlen = 0;
	int ret, len, oidmatch, hashmatch;
	const u_char *oid = NULL;
	u_char *decrypted = NULL;

	if ((ret = rsa_hash_alg_oid(hash_alg, &oid, &oidlen)) != 0)
		return ret;
	ret = SSH_ERR_INTERNAL_ERROR;
	hlen = ssh_digest_bytes(hash_alg);
	if (hashlen != hlen) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		goto done;
	}
	rsasize = RSA_size(rsa);
	if (rsasize <= 0 || rsasize > SSHBUF_MAX_BIGNUM ||
	    siglen == 0 || siglen > rsasize) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		goto done;
	}
	if ((decrypted = malloc(rsasize)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto done;
	}
	if ((len = RSA_public_decrypt(siglen, sigbuf, decrypted, rsa,
	    RSA_PKCS1_PADDING)) < 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto done;
	}
	if (len < 0 || (size_t)len != hlen + oidlen) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto done;
	}
	oidmatch = timingsafe_bcmp(decrypted, oid, oidlen) == 0;
	hashmatch = timingsafe_bcmp(decrypted + oidlen, hash, hlen) == 0;
	if (!oidmatch || !hashmatch) {
		ret = SSH_ERR_SIGNATURE_INVALID;
		goto done;
	}
	ret = 0;
done:
	freezero(decrypted, rsasize);
	return ret;
}

static int
ssh_rsa_new_key_openssl(struct sshkey *key, struct ssh_rsa_key_params *rsa_param, struct ssh_rsa_exponents *rsa_exp)
{
	if (key->rsa == NULL) {
		return SSH_ERR_INVALID_ARGUMENT;
	}

	if (!RSA_set0_key(key->rsa, rsa_param->n, rsa_param->e, rsa_param->d)) {
		return SSH_ERR_LIBCRYPTO_ERROR;
	}

	/* transferred */
	rsa_param->n = NULL;
	rsa_param->e = NULL;
	rsa_param->d = NULL;

	if (rsa_param->p != NULL && rsa_param->q) {
		if (!RSA_set0_factors(key->rsa, rsa_param->p, rsa_param->q)) {
			return SSH_ERR_LIBCRYPTO_ERROR;
		}
	}

	/* transferred */
	rsa_param->p = NULL;
	rsa_param->q = NULL;

	if (rsa_exp->dmp1 != NULL &&  rsa_exp->dmq1 != NULL &&
	    rsa_param->iqmp != NULL) {
		if (!RSA_set0_crt_params(key->rsa, rsa_exp->dmp1,
		    rsa_exp->dmq1, rsa_param->iqmp)) {
			return SSH_ERR_LIBCRYPTO_ERROR;
		}
	}

	/* transferred */
	rsa_exp->dmp1 = NULL;
	rsa_exp->dmq1 = NULL;
	rsa_param->iqmp = NULL;
	return 0;
}

#endif /* OPENSSL_VERSION_NUMBER >= 0x3000000L */

int
ssh_rsa_new_key(struct sshkey *key, struct ssh_rsa_key_params *rsa_param)
{
	BIGNUM *aux = NULL, *d_consttime = NULL;
	struct ssh_rsa_exponents rsa_exp;
	BN_CTX *ctx = NULL;
	int r;

	memset(&rsa_exp, 0, sizeof rsa_exp);
	if (key == NULL || rsa_param == NULL ||
	    sshkey_type_plain(key->type) != KEY_RSA)
		return SSH_ERR_INVALID_ARGUMENT;

	if ((ctx = BN_CTX_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;

	if (rsa_param->d != NULL &&
	    rsa_param->p != NULL &&
	    rsa_param->q != NULL) {
		if ((aux = BN_new()) == NULL ||
		    (rsa_exp.dmq1 = BN_new()) == NULL ||
		    (rsa_exp.dmp1 = BN_new()) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}

		if ((d_consttime = BN_dup(rsa_param->d)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}

		BN_set_flags(aux, BN_FLG_CONSTTIME);
		BN_set_flags(d_consttime, BN_FLG_CONSTTIME);

		if ((BN_sub(aux, rsa_param->q, BN_value_one()) == 0) ||
		    (BN_mod(rsa_exp.dmq1, d_consttime, aux, ctx) == 0) ||
		    (BN_sub(aux, rsa_param->p, BN_value_one()) == 0) ||
		    (BN_mod(rsa_exp.dmp1, d_consttime, aux, ctx) == 0)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
	}

	r = ssh_rsa_new_key_openssl(key, rsa_param, &rsa_exp);
	if (r != 0) {
		goto out;
	}

	/* success */
	r = 0;
 out:
	BN_clear_free(aux);
	BN_clear_free(d_consttime);
	BN_clear_free(rsa_exp.dmp1);
	BN_clear_free(rsa_exp.dmq1);
	BN_CTX_free(ctx);
	return r;
}

void
ssh_rsa_key_params_deinit(struct ssh_rsa_key_params *param)
{
	BN_clear_free(param->n);
	BN_clear_free(param->e);
	BN_clear_free(param->d);
	BN_clear_free(param->p);
	BN_clear_free(param->q);
	BN_clear_free(param->iqmp);
	memset(param, 0, sizeof *param);
}

#endif /* WITH_OPENSSL */
