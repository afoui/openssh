/* $OpenBSD: ssh-dss.c,v 1.39 2020/02/26 13:40:09 jsg Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#ifdef WITH_OPENSSL

#include <sys/types.h>

#include <openssl/bn.h>
#include <openssl/dsa.h>
#include <openssl/evp.h>

#include <stdarg.h>
#include <string.h>

#include "sshbuf.h"
#include "compat.h"
#include "ssherr.h"
#include "digest.h"
#define SSHKEY_INTERNAL
#include "sshkey.h"

#include "openbsd-compat/openssl-compat.h"

#define INTBLOB_LEN	20
#define SIGBLOB_LEN	(2*INTBLOB_LEN)

# if OPENSSL_VERSION_NUMBER >= 0x3000000L

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/param_build.h>

static int
push_opt_bn(OSSL_PARAM_BLD *bld, const char *key, BIGNUM *bn)
{
	if (bn != NULL) {
		if (OSSL_PARAM_BLD_push_BN(bld, key, bn) != 1) {
			return -1;
		}
	}

	return 0;
}

int
ssh_dsa_new_key(struct sshkey *key, struct ssh_dsa_key_params *dsa_param)
{
	int r = SSH_ERR_LIBCRYPTO_ERROR;
	EVP_PKEY_CTX *kctx = NULL;
	OSSL_PARAM_BLD *param_bld = NULL;
	OSSL_PARAM *param = NULL;

	EVP_PKEY_free(key->pkey);
	key->pkey = NULL;

	if ((kctx = EVP_PKEY_CTX_new_from_name(NULL, "DSA", NULL)) == NULL) {
		goto out;
	}

	if (EVP_PKEY_fromdata_init(kctx) != 1) {
		goto out;
	}

	if ((param_bld = OSSL_PARAM_BLD_new()) == NULL) {
		goto out;
	}

	if (push_opt_bn(param_bld, OSSL_PKEY_PARAM_PUB_KEY, dsa_param->pub_key) < 0 ||
	    push_opt_bn(param_bld, OSSL_PKEY_PARAM_PRIV_KEY, dsa_param->priv_key) < 0 ||
	    push_opt_bn(param_bld, OSSL_PKEY_PARAM_FFC_P, dsa_param->p) < 0 ||
	    push_opt_bn(param_bld, OSSL_PKEY_PARAM_FFC_G, dsa_param->g) < 0 ||
	    push_opt_bn(param_bld, OSSL_PKEY_PARAM_FFC_Q, dsa_param->q) < 0) {
		goto out;
	}

	if ((param = OSSL_PARAM_BLD_to_param(param_bld)) == NULL) {
		goto out;
	}

	if (EVP_PKEY_fromdata(kctx, &key->pkey, EVP_PKEY_KEYPAIR, param) != 1) {
		goto out;
	}

#ifdef DEBUG_PK
	EVP_PKEY_print_private_fp(stdout, key->pkey, 8, NULL);
#endif

	r = 0;

out:
	OSSL_PARAM_free(param);
	OSSL_PARAM_BLD_free(param_bld);
	EVP_PKEY_CTX_free(kctx);
	return r;
}

int
ssh_get_dsa_key_params(const struct sshkey *key, struct ssh_dsa_key_params *dsa_param, int private)
{
	int r = SSH_ERR_LIBCRYPTO_ERROR;

	if (EVP_PKEY_get_bn_param(key->pkey, OSSL_PKEY_PARAM_FFC_P, &dsa_param->p) != 1 ||
	    EVP_PKEY_get_bn_param(key->pkey, OSSL_PKEY_PARAM_FFC_Q, &dsa_param->q) != 1 ||
	    EVP_PKEY_get_bn_param(key->pkey, OSSL_PKEY_PARAM_FFC_G, &dsa_param->g) != 1 ||
	    EVP_PKEY_get_bn_param(key->pkey, OSSL_PKEY_PARAM_PUB_KEY, &dsa_param->pub_key) != 1) {
		goto out;
	}

	if (private) {
		if (EVP_PKEY_get_bn_param(key->pkey, OSSL_PKEY_PARAM_PRIV_KEY, &dsa_param->priv_key) != 1) {
			goto out;
		}
	}

	r = 0;
out:
	return r;
}

int
ssh_dss_sign(const struct sshkey *key, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen, u_int compat)
{
	int ret;
	EVP_MD_CTX *ctx = NULL;
	size_t siglen = 0;
	unsigned char *sig = NULL;
	const unsigned char *p = NULL;
	struct sshbuf *b = NULL;
	size_t len;
	DSA_SIG *dsa_sig = NULL;
	const BIGNUM *sig_r, *sig_s;
	int rlen, slen;
	u_char sigblob[SIGBLOB_LEN];

	if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;

	if (key == NULL || key->pkey == NULL ||
	    EVP_PKEY_get_base_id(key->pkey) != EVP_PKEY_DSA ||
	    sshkey_type_plain(key->type) != KEY_DSA)
		return SSH_ERR_INVALID_ARGUMENT;

	if ((ctx = EVP_MD_CTX_new()) == NULL) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	if (EVP_DigestSignInit_ex(ctx, NULL, OSSL_DIGEST_NAME_SHA1, NULL, NULL, key->pkey, NULL) != 1) {
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

	p = sig;
	dsa_sig = d2i_DSA_SIG(NULL, &p, siglen);
	if (dsa_sig == NULL) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	DSA_SIG_get0(dsa_sig, &sig_r, &sig_s);
	rlen = BN_num_bytes(sig_r);
	slen = BN_num_bytes(sig_s);
	if (rlen > INTBLOB_LEN || slen > INTBLOB_LEN) {
		ret = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	explicit_bzero(sigblob, SIGBLOB_LEN);
	BN_bn2bin(sig_r, sigblob + SIGBLOB_LEN - INTBLOB_LEN - rlen);
	BN_bn2bin(sig_s, sigblob + SIGBLOB_LEN - slen);

	if ((b = sshbuf_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((ret = sshbuf_put_cstring(b, "ssh-dss")) != 0 ||
	    (ret = sshbuf_put_string(b, sigblob, SIGBLOB_LEN)) != 0)
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
	DSA_SIG_free(dsa_sig);
	free(sig);
	sshbuf_free(b);
	EVP_MD_CTX_free(ctx);
	return ret;
}

int
ssh_dss_verify(const struct sshkey *key,
    const u_char *signature, size_t signaturelen,
    const u_char *data, size_t datalen, u_int compat)
{
	EVP_MD_CTX *ctx = NULL;
	DSA_SIG *sig = NULL;
	BIGNUM *sig_r = NULL, *sig_s = NULL;
	u_char digest[SSH_DIGEST_MAX_LENGTH], *sigblob = NULL;
	size_t len;
	int ret = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *b = NULL;
	char *ktype = NULL;
	u_char *sigbytes = NULL;
	int siglen;
	unsigned char *p;

	if (key == NULL || key->pkey == NULL ||
	    EVP_PKEY_get_base_id(key->pkey) != EVP_PKEY_DSA ||
	    sshkey_type_plain(key->type) != KEY_DSA ||
	    signature == NULL || signaturelen == 0) {
		return SSH_ERR_INVALID_ARGUMENT;
	}

	/* fetch signature */
	if ((b = sshbuf_from(signature, signaturelen)) == NULL) {
		return SSH_ERR_ALLOC_FAIL;
	}

	if (sshbuf_get_cstring(b, &ktype, NULL) != 0 ||
	    sshbuf_get_string(b, &sigblob, &len) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	if (strcmp("ssh-dss", ktype) != 0) {
		ret = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}

	if (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}

	if (len != SIGBLOB_LEN) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* parse signature */
	if ((sig = DSA_SIG_new()) == NULL ||
	    (sig_r = BN_new()) == NULL ||
	    (sig_s = BN_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((BN_bin2bn(sigblob, INTBLOB_LEN, sig_r) == NULL) ||
	    (BN_bin2bn(sigblob + INTBLOB_LEN, INTBLOB_LEN, sig_s) == NULL)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	if (!DSA_SIG_set0(sig, sig_r, sig_s)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	sig_r = sig_s = NULL; /* transferred */

	siglen = i2d_DSA_SIG(sig, NULL);
	if (siglen <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	if ((sigbytes = malloc(siglen)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	p = sigbytes;
	if (i2d_DSA_SIG(sig, &p) != siglen) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	if ((ctx = EVP_MD_CTX_new()) == NULL) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	if (EVP_DigestVerifyInit_ex(ctx, NULL, OSSL_DIGEST_NAME_SHA1, NULL, NULL, key->pkey, NULL) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	if (EVP_DigestVerify(ctx, sigbytes, siglen, data, datalen) != 1) {
		ret = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}

	ret = 0;

out:
	free(sigbytes);
	explicit_bzero(digest, sizeof(digest));
	EVP_MD_CTX_free(ctx);
	DSA_SIG_free(sig);
	BN_clear_free(sig_r);
	BN_clear_free(sig_s);
	sshbuf_free(b);
	free(ktype);
	if (sigblob != NULL)
		freezero(sigblob, len);
	return ret;
}
# else

int
ssh_dsa_new_key(struct sshkey *key, struct ssh_dsa_key_params *dsa_param)
{
	int r = SSH_ERR_LIBCRYPTO_ERROR;

	if ((key->dsa = DSA_new()) == NULL) {
		goto out;
	}

	if (DSA_set0_pqg(key->dsa, dsa_param->p, dsa_param->q, dsa_param->g) != 1) {
		goto out;
	}

	dsa_param->p = NULL;
	dsa_param->q = NULL;
	dsa_param->g = NULL;

	if (DSA_set0_key(key->dsa, dsa_param->pub_key, dsa_param->priv_key) != 1) {
		goto out;
	}

	dsa_param->pub_key = NULL;
	dsa_param->priv_key = NULL;

	r = 0;

out:
	return r;
}

int
ssh_dss_sign(const struct sshkey *key, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen, u_int compat)
{
	DSA_SIG *sig = NULL;
	const BIGNUM *sig_r, *sig_s;
	u_char digest[SSH_DIGEST_MAX_LENGTH], sigblob[SIGBLOB_LEN];
	size_t rlen, slen, len, dlen = ssh_digest_bytes(SSH_DIGEST_SHA1);
	struct sshbuf *b = NULL;
	int ret = SSH_ERR_INVALID_ARGUMENT;

	if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;

	if (key == NULL || key->dsa == NULL ||
	    sshkey_type_plain(key->type) != KEY_DSA)
		return SSH_ERR_INVALID_ARGUMENT;
	if (dlen == 0)
		return SSH_ERR_INTERNAL_ERROR;

	if ((ret = ssh_digest_memory(SSH_DIGEST_SHA1, data, datalen,
	    digest, sizeof(digest))) != 0)
		goto out;

	if ((sig = DSA_do_sign(digest, dlen, key->dsa)) == NULL) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	DSA_SIG_get0(sig, &sig_r, &sig_s);
	rlen = BN_num_bytes(sig_r);
	slen = BN_num_bytes(sig_s);
	if (rlen > INTBLOB_LEN || slen > INTBLOB_LEN) {
		ret = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	explicit_bzero(sigblob, SIGBLOB_LEN);
	BN_bn2bin(sig_r, sigblob + SIGBLOB_LEN - INTBLOB_LEN - rlen);
	BN_bn2bin(sig_s, sigblob + SIGBLOB_LEN - slen);

	if ((b = sshbuf_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((ret = sshbuf_put_cstring(b, "ssh-dss")) != 0 ||
	    (ret = sshbuf_put_string(b, sigblob, SIGBLOB_LEN)) != 0)
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
	DSA_SIG_free(sig);
	sshbuf_free(b);
	return ret;
}

int
ssh_dss_verify(const struct sshkey *key,
    const u_char *signature, size_t signaturelen,
    const u_char *data, size_t datalen, u_int compat)
{
	DSA_SIG *sig = NULL;
	BIGNUM *sig_r = NULL, *sig_s = NULL;
	u_char digest[SSH_DIGEST_MAX_LENGTH], *sigblob = NULL;
	size_t len, dlen = ssh_digest_bytes(SSH_DIGEST_SHA1);
	int ret = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *b = NULL;
	char *ktype = NULL;

	if (key == NULL || key->dsa == NULL ||
	    sshkey_type_plain(key->type) != KEY_DSA ||
	    signature == NULL || signaturelen == 0)
		return SSH_ERR_INVALID_ARGUMENT;
	if (dlen == 0)
		return SSH_ERR_INTERNAL_ERROR;

	/* fetch signature */
	if ((b = sshbuf_from(signature, signaturelen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (sshbuf_get_cstring(b, &ktype, NULL) != 0 ||
	    sshbuf_get_string(b, &sigblob, &len) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (strcmp("ssh-dss", ktype) != 0) {
		ret = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}
	if (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}

	if (len != SIGBLOB_LEN) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/* parse signature */
	if ((sig = DSA_SIG_new()) == NULL ||
	    (sig_r = BN_new()) == NULL ||
	    (sig_s = BN_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((BN_bin2bn(sigblob, INTBLOB_LEN, sig_r) == NULL) ||
	    (BN_bin2bn(sigblob + INTBLOB_LEN, INTBLOB_LEN, sig_s) == NULL)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if (!DSA_SIG_set0(sig, sig_r, sig_s)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	sig_r = sig_s = NULL; /* transferred */

	/* sha1 the data */
	if ((ret = ssh_digest_memory(SSH_DIGEST_SHA1, data, datalen,
	    digest, sizeof(digest))) != 0)
		goto out;

	switch (DSA_do_verify(digest, dlen, sig, key->dsa)) {
	case 1:
		ret = 0;
		break;
	case 0:
		ret = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	default:
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

 out:
	explicit_bzero(digest, sizeof(digest));
	DSA_SIG_free(sig);
	BN_clear_free(sig_r);
	BN_clear_free(sig_s);
	sshbuf_free(b);
	free(ktype);
	if (sigblob != NULL)
		freezero(sigblob, len);
	return ret;
}
#endif /* OPENSSL_VERSION_NUMBER >= 0x3000000L */

void
ssh_dsa_key_params_deinit(struct ssh_dsa_key_params *param)
{
	BN_clear_free(param->p);
	BN_clear_free(param->g);
	BN_clear_free(param->q);
	BN_clear_free(param->pub_key);
	BN_clear_free(param->priv_key);
	memset(param, 0, sizeof *param);
}

#endif /* WITH_OPENSSL */
