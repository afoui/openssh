/* $OpenBSD: ssh-ecdsa.c,v 1.16 2019/01/21 09:54:11 djm Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 * Copyright (c) 2010 Damien Miller.  All rights reserved.
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

#if defined(WITH_OPENSSL) && defined(OPENSSL_HAS_ECC)

#include <sys/types.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>

#include <string.h>

#include "sshbuf.h"
#include "ssherr.h"
#include "digest.h"
#define SSHKEY_INTERNAL
#include "sshkey.h"

#include "openbsd-compat/openssl-compat.h"

# if OPENSSL_VERSION_NUMBER >= 0x3000000L

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/param_build.h>

static int
push_opt_utf8(OSSL_PARAM_BLD *bld, const char *key, const char *v, size_t len)
{
	if (v != NULL) {
		if (OSSL_PARAM_BLD_push_utf8_string(bld, key, v, len) != 1) {
			return -1;
		}
	}

	return 0;
}

static int
push_opt_oct(OSSL_PARAM_BLD *bld, const char *key, const unsigned char *v, size_t len)
{
	if (v != NULL) {
		if (OSSL_PARAM_BLD_push_octet_string(bld, key, v, len) != 1) {
			return -1;
		}
	}

	return 0;
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

static const char *
ec_nid_to_mdname(int nid)
{
	int hash_alg;

	if ((hash_alg = sshkey_ec_nid_to_hash_alg(nid)) < 0) {
		return NULL;
	}

	switch (hash_alg) {
	case SSH_DIGEST_SHA256:
		return OSSL_DIGEST_NAME_SHA2_256;
	case SSH_DIGEST_SHA384:
		return OSSL_DIGEST_NAME_SHA2_384;
	case SSH_DIGEST_SHA512:
		return OSSL_DIGEST_NAME_SHA2_512;
	default:
		return NULL;
	}
}

int
ssh_ecdsa_sign(const struct sshkey *key, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen, u_int compat)
{
	int ret;
	EVP_MD_CTX *ctx = NULL;
	const char *mdname = NULL;
	size_t siglen = 0;
	unsigned char *sig = NULL;
	const unsigned char *p = NULL;
	struct sshbuf *b = NULL, *bb = NULL;
	ECDSA_SIG *ecdsa_sig = NULL;
	const BIGNUM *sig_r = NULL, *sig_s = NULL;
	size_t len;

	if (lenp != NULL) {
		*lenp = 0;
	}

	if (sigp != NULL) {
		*sigp = NULL;
	}

	if (key == NULL || key->pkey == NULL ||
	    EVP_PKEY_get_base_id(key->pkey) != EVP_PKEY_EC ||
	    sshkey_type_plain(key->type) != KEY_ECDSA) {
		return SSH_ERR_INVALID_ARGUMENT;
	}

	if ((ctx = EVP_MD_CTX_new()) == NULL) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	if ((mdname = ec_nid_to_mdname(key->ecdsa_nid)) == NULL) {
		ret = SSH_ERR_INTERNAL_ERROR;
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

	p = sig;
	ecdsa_sig = d2i_ECDSA_SIG(NULL, &p, siglen);
	if (ecdsa_sig == NULL) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	if ((bb = sshbuf_new()) == NULL || (b = sshbuf_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	ECDSA_SIG_get0(ecdsa_sig, &sig_r, &sig_s);
	if ((ret = sshbuf_put_bignum2(bb, sig_r)) != 0 ||
	    (ret = sshbuf_put_bignum2(bb, sig_s)) != 0)
		goto out;
	if ((ret = sshbuf_put_cstring(b, sshkey_ssh_name_plain(key))) != 0 ||
	    (ret = sshbuf_put_stringb(b, bb)) != 0)
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
	ECDSA_SIG_free(ecdsa_sig);
	freezero(sig, siglen);
	sshbuf_free(b);
	sshbuf_free(bb);
	EVP_MD_CTX_free(ctx);
	return ret;
}

int
ssh_ecdsa_verify(const struct sshkey *key,
    const u_char *signature, size_t signaturelen,
    const u_char *data, size_t datalen, u_int compat)
{
	EVP_MD_CTX *ctx = NULL;
	const char *mdname = NULL;
	ECDSA_SIG *sig = NULL;
	BIGNUM *sig_r = NULL, *sig_s = NULL;
	int hash_alg;
	int ret = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *b = NULL, *sigbuf = NULL;
	char *ktype = NULL;
	u_char *sigbytes = NULL;
	int siglen;
	unsigned char *p;

	if (key == NULL || key->pkey == NULL ||
	    EVP_PKEY_get_base_id(key->pkey) != EVP_PKEY_EC ||
	    sshkey_type_plain(key->type) != KEY_ECDSA ||
	    signature == NULL || signaturelen == 0)
		return SSH_ERR_INVALID_ARGUMENT;

	if ((hash_alg = sshkey_ec_nid_to_hash_alg(key->ecdsa_nid)) == -1) {
		return SSH_ERR_INTERNAL_ERROR;
	}

	/* fetch signature */
	if ((b = sshbuf_from(signature, signaturelen)) == NULL) {
		return SSH_ERR_ALLOC_FAIL;
	}

	if (sshbuf_get_cstring(b, &ktype, NULL) != 0 ||
	    sshbuf_froms(b, &sigbuf) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	if (strcmp(sshkey_ssh_name_plain(key), ktype) != 0) {
		ret = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}

	if (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}

	/* parse signature */
	if (sshbuf_get_bignum2(sigbuf, &sig_r) != 0 ||
	    sshbuf_get_bignum2(sigbuf, &sig_s) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	if ((sig = ECDSA_SIG_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if (!ECDSA_SIG_set0(sig, sig_r, sig_s)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	sig_r = sig_s = NULL; /* transferred */

	if (sshbuf_len(sigbuf) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}

	siglen = i2d_ECDSA_SIG(sig, NULL);
	if (siglen <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	if ((sigbytes = malloc(siglen)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	p = sigbytes;
	if (i2d_ECDSA_SIG(sig, &p) != siglen) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	if ((ctx = EVP_MD_CTX_new()) == NULL) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	if ((mdname = ec_nid_to_mdname(key->ecdsa_nid)) == NULL) {
		ret = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	if (EVP_DigestVerifyInit_ex(ctx, NULL, mdname, NULL, NULL, key->pkey, NULL) != 1) {
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
	sshbuf_free(sigbuf);
	sshbuf_free(b);
	ECDSA_SIG_free(sig);
	BN_clear_free(sig_r);
	BN_clear_free(sig_s);
	free(ktype);
	EVP_MD_CTX_free(ctx);
	return ret;
}

int
ssh_ec_new_key(struct sshkey *key, struct ssh_ec_key_params *ec_param)
{
	int r = SSH_ERR_LIBCRYPTO_ERROR;
	EVP_PKEY_CTX *kctx = NULL;
	OSSL_PARAM_BLD *param_bld = NULL;
	OSSL_PARAM *param = NULL;
	const char *group_name = NULL;

	EVP_PKEY_free(key->pkey);
	key->pkey = NULL;

	if ((kctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL)) == NULL) {
		goto out;
	}

	if (EVP_PKEY_fromdata_init(kctx) != 1) {
		goto out;
	}

	if ((param_bld = OSSL_PARAM_BLD_new()) == NULL) {
		goto out;
	}

	if ((group_name = OBJ_nid2sn(ec_param->curve_nid)) == NULL) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}

	if (push_opt_utf8(param_bld, OSSL_PKEY_PARAM_GROUP_NAME, group_name, 0) < 0 ||
	    push_opt_oct(param_bld, OSSL_PKEY_PARAM_PUB_KEY, ec_param->pub, ec_param->pub_len) < 0 ||
	    push_opt_bn(param_bld, OSSL_PKEY_PARAM_PRIV_KEY, ec_param->exponent) < 0) {
		goto out;
	}

	if ((param = OSSL_PARAM_BLD_to_param(param_bld)) == NULL) {
		goto out;
	}

	if (EVP_PKEY_fromdata(kctx, &key->pkey, EVP_PKEY_KEYPAIR, param) != 1) {
		goto out;
	}

#ifdef DEBUG_PK
	fprintf(stderr, "%s\n", __PRETTY_FUNCTION__);
	EVP_PKEY_print_private_fp(stdout, key->pkey, 8, NULL);
#endif

	key->ecdsa_nid = ec_param->curve_nid;
	r = 0;

out:
	OSSL_PARAM_free(param);
	OSSL_PARAM_BLD_free(param_bld);
	EVP_PKEY_CTX_free(kctx);
	return r;
}

static int
evp_pkey_get_new_octet_string_param(EVP_PKEY *pkey, const char *name, unsigned char **vp, size_t *lenp)
{
	size_t size = 0;
	unsigned char *v = NULL;
	size_t len = 0;
	int r;

	if (EVP_PKEY_get_octet_string_param(pkey, name, NULL, 0, &size) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	if ((v = malloc(size)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if (EVP_PKEY_get_octet_string_param(pkey, name, v, size, &len) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	*vp = v;
	v = NULL;
	*lenp = len;
	len = 0;
	r = 0;

out:
	freezero(v, size);
	return r;
}

int
ssh_get_ec_key_params(EVP_PKEY *pkey, struct ssh_ec_key_params *ec_param, int private)
{
	int r = SSH_ERR_LIBCRYPTO_ERROR;
	char curve_name[80];
	int nid;
	unsigned char *pub = NULL;
	size_t pub_len = 0;
	BIGNUM *priv = NULL;

	if (EVP_PKEY_get_group_name(pkey, curve_name, sizeof curve_name, NULL) != 1) {
		goto out;
	}

	if ((nid = OBJ_txt2nid(curve_name)) == NID_undef) {
		goto out;
	}

	if ((r = evp_pkey_get_new_octet_string_param(pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, &pub, &pub_len)) != 0) {
		goto out;
	}

	if (pub[0] != POINT_CONVERSION_UNCOMPRESSED) {
		fprintf(stderr, "%s: TODO\n", __func__);
		abort(); // TODO: convert to uncompressed format
	}

	if (private) {
		if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv) != 1) {
			goto out;
		}
	}

	ec_param->curve_nid = nid;
	ec_param->pub = pub;
	pub = NULL;
	ec_param->pub_len = pub_len;
	ec_param->exponent = priv;
	priv = NULL;

	r = 0;

out:
	BN_clear_free(priv);
	free(pub);
	return r;
}
# else
/* ARGSUSED */
int
ssh_ecdsa_sign(const struct sshkey *key, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen, u_int compat)
{
	ECDSA_SIG *sig = NULL;
	const BIGNUM *sig_r, *sig_s;
	int hash_alg;
	u_char digest[SSH_DIGEST_MAX_LENGTH];
	size_t len, dlen;
	struct sshbuf *b = NULL, *bb = NULL;
	int ret = SSH_ERR_INTERNAL_ERROR;

	if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;

	if (key == NULL || key->ecdsa == NULL ||
	    sshkey_type_plain(key->type) != KEY_ECDSA)
		return SSH_ERR_INVALID_ARGUMENT;

	if ((hash_alg = sshkey_ec_nid_to_hash_alg(key->ecdsa_nid)) == -1 ||
	    (dlen = ssh_digest_bytes(hash_alg)) == 0)
		return SSH_ERR_INTERNAL_ERROR;
	if ((ret = ssh_digest_memory(hash_alg, data, datalen,
	    digest, sizeof(digest))) != 0)
		goto out;

	if ((sig = ECDSA_do_sign(digest, dlen, key->ecdsa)) == NULL) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	if ((bb = sshbuf_new()) == NULL || (b = sshbuf_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	if ((ret = sshbuf_put_bignum2(bb, sig_r)) != 0 ||
	    (ret = sshbuf_put_bignum2(bb, sig_s)) != 0)
		goto out;
	if ((ret = sshbuf_put_cstring(b, sshkey_ssh_name_plain(key))) != 0 ||
	    (ret = sshbuf_put_stringb(b, bb)) != 0)
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
	sshbuf_free(b);
	sshbuf_free(bb);
	ECDSA_SIG_free(sig);
	return ret;
}

/* ARGSUSED */
int
ssh_ecdsa_verify(const struct sshkey *key,
    const u_char *signature, size_t signaturelen,
    const u_char *data, size_t datalen, u_int compat)
{
	ECDSA_SIG *sig = NULL;
	BIGNUM *sig_r = NULL, *sig_s = NULL;
	int hash_alg;
	u_char digest[SSH_DIGEST_MAX_LENGTH];
	size_t dlen;
	int ret = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *b = NULL, *sigbuf = NULL;
	char *ktype = NULL;

	if (key == NULL || key->ecdsa == NULL ||
	    sshkey_type_plain(key->type) != KEY_ECDSA ||
	    signature == NULL || signaturelen == 0)
		return SSH_ERR_INVALID_ARGUMENT;

	if ((hash_alg = sshkey_ec_nid_to_hash_alg(key->ecdsa_nid)) == -1 ||
	    (dlen = ssh_digest_bytes(hash_alg)) == 0)
		return SSH_ERR_INTERNAL_ERROR;

	/* fetch signature */
	if ((b = sshbuf_from(signature, signaturelen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (sshbuf_get_cstring(b, &ktype, NULL) != 0 ||
	    sshbuf_froms(b, &sigbuf) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (strcmp(sshkey_ssh_name_plain(key), ktype) != 0) {
		ret = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}
	if (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}

	/* parse signature */
	if (sshbuf_get_bignum2(sigbuf, &sig_r) != 0 ||
	    sshbuf_get_bignum2(sigbuf, &sig_s) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if ((sig = ECDSA_SIG_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (!ECDSA_SIG_set0(sig, sig_r, sig_s)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	sig_r = sig_s = NULL; /* transferred */

	if (sshbuf_len(sigbuf) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}
	if ((ret = ssh_digest_memory(hash_alg, data, datalen,
	    digest, sizeof(digest))) != 0)
		goto out;

	switch (ECDSA_do_verify(digest, dlen, sig, key->ecdsa)) {
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
	sshbuf_free(sigbuf);
	sshbuf_free(b);
	ECDSA_SIG_free(sig);
	BN_clear_free(sig_r);
	BN_clear_free(sig_s);
	free(ktype);
	return ret;
}

#endif /* OPENSSL_VERSION_NUMBER >= 0x3000000L */

void
ssh_ec_key_params_deinit(struct ssh_ec_key_params *param)
{
	free(param->pub);
	BN_clear_free(param->exponent);
	memset(param, 0, sizeof *param);
}

#endif /* WITH_OPENSSL && OPENSSL_HAS_ECC */
