/* $OpenBSD: kexecdh.c,v 1.10 2019/01/21 10:40:11 djm Exp $ */
/*
 * Copyright (c) 2010 Damien Miller.  All rights reserved.
 * Copyright (c) 2019 Markus Friedl.  All rights reserved.
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

#include <stdio.h>
#include <string.h>
#include <signal.h>

#include <openssl/ecdh.h>

#include "sshkey.h"
#include "kex.h"
#include "sshbuf.h"
#include "digest.h"
#include "ssherr.h"

#if OPENSSL_VERSION_NUMBER >= 0x3000000L

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/param_build.h>

static int generate_ec_pkey_from_nid(int nid, EVP_PKEY **pkeyp)
{
	EVP_PKEY_CTX *ctx = NULL;
	const char *group_name = NULL;
	int r = SSH_ERR_LIBCRYPTO_ERROR;

	if ((group_name = OBJ_nid2sn(nid)) == NULL) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}

	ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	if (ctx == NULL) {
		goto out;
	}

	if (EVP_PKEY_keygen_init(ctx) != 1) {
		goto out;
	}

	if (EVP_PKEY_CTX_set_group_name(ctx, group_name) != 1) {
		goto out;
	}

	if (EVP_PKEY_generate(ctx, pkeyp) != 1) {
		goto out;
	}

	r = 0;

out:
	EVP_PKEY_CTX_free(ctx);
	return r;
}

int
kex_ecdh_keypair(struct kex *kex)
{
	EVP_PKEY *client_key = NULL;
	struct sshbuf *buf = NULL;
	int r;

	if ((r = generate_ec_pkey_from_nid(kex->ec_nid, &client_key)) != 0) {
		goto out;
	}

	if ((buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if ((r = sshbuf_put_evp_pkey_ec(buf, client_key, 0)) != 0) {
		goto out;
	}

	if ((r = sshbuf_get_u32(buf, NULL)) != 0) {
		goto out;
	}
#ifdef DEBUG_KEXECDH
	fputs("client private key:\n", stderr);
	EVP_PKEY_print_private_fp(stderr, client_key, 8, NULL);
#endif
	kex->ec_client_key = client_key;
	client_key = NULL;	/* owned by the kex */
	kex->client_pub = buf;
	buf = NULL;
	r = 0;
 out:
	EVP_PKEY_free(client_key);
	sshbuf_free(buf);
	return r;
}

static int
make_evp_pkey_from_ec_pub_key_bytes(
	const char *group_name, size_t gname_len,
	const unsigned char *pub_key_bytes, size_t pub_key_len,
	EVP_PKEY **pkeyp)
{
	EVP_PKEY_CTX *ctx = NULL;
	OSSL_PARAM_BLD *param_bld = NULL;
	OSSL_PARAM *param = NULL;
	int r = SSH_ERR_LIBCRYPTO_ERROR;

	ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	if (ctx == NULL) {
		goto out;
	}

	if (EVP_PKEY_fromdata_init(ctx) != 1) {
		goto out;
	}

	if ((param_bld = OSSL_PARAM_BLD_new()) == NULL) {
		goto out;
	}

	if (OSSL_PARAM_BLD_push_utf8_string(param_bld, OSSL_PKEY_PARAM_GROUP_NAME, group_name, gname_len) != 1) {
		goto out;
	}

	if (OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_PUB_KEY, pub_key_bytes, pub_key_len) != 1) {
		goto out;
	}

	if ((param = OSSL_PARAM_BLD_to_param(param_bld)) == NULL) {
		goto out;
	}

	if (EVP_PKEY_fromdata(ctx, pkeyp, EVP_PKEY_PUBLIC_KEY, param) != 1) {
		ERR_print_errors_fp(stderr);
		goto out;
	}

	r = 0;

out:
	OSSL_PARAM_free(param);
	OSSL_PARAM_BLD_free(param_bld);
	EVP_PKEY_CTX_free(ctx);
	return r;
}

static int
derive_secret(EVP_PKEY *host_key, EVP_PKEY *pub_key, struct sshbuf *shared_secret)
{
	EVP_PKEY_CTX *ctx = NULL;
	int r = SSH_ERR_LIBCRYPTO_ERROR;
	size_t sslen = 0;
	unsigned char *ss = NULL;
	BIGNUM *ssbn = NULL;

	if ((ctx = EVP_PKEY_CTX_new_from_pkey(NULL, host_key, NULL)) == NULL) {
		goto out;
	}

	if (EVP_PKEY_derive_init(ctx) != 1) {
		goto out;
	}

	if (EVP_PKEY_derive_set_peer(ctx, pub_key) != 1) {
		goto out;
	}

	if (EVP_PKEY_derive(ctx, NULL, &sslen) != 1) {
		goto out;
	}

	if ((ss = malloc(sslen)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if (EVP_PKEY_derive(ctx, ss, &sslen) != 1) {
		goto out;
	}

#ifdef DEBUG_KEXECDH
	dump_digest("shared secret", ss, sslen);
#endif

	if ((ssbn = BN_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if (BN_bin2bn(ss, sslen, ssbn) == NULL) {
		goto out;
	}

	r = sshbuf_put_bignum2(shared_secret, ssbn);

out:
	freezero(ss, sslen);
	BN_free(ssbn);
	EVP_PKEY_CTX_free(ctx);
	return r;
}

static int
kex_ecdh_dec_key(struct kex *kex, const struct sshbuf *ec_blob,
    EVP_PKEY *pkey, struct sshbuf **shared_secretp)
{
	struct sshbuf *buf = NULL;
	int r;
	const u_char *pub_key_bytes = NULL;
	size_t pub_key_len = 0;
	char group_name[0x80];
	size_t gname_len = 0;
	EVP_PKEY *pub_key = NULL;

	*shared_secretp = NULL;

	if ((buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_put_stringb(buf, ec_blob)) != 0)
		goto out;

	if ((r = sshbuf_get_string_direct(buf, &pub_key_bytes, &pub_key_len)) != 0) {
		goto out;
	}

	if (EVP_PKEY_get_group_name(pkey, group_name, sizeof group_name, &gname_len) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	r = make_evp_pkey_from_ec_pub_key_bytes(group_name, gname_len, pub_key_bytes, pub_key_len, &pub_key);
	if (r != 0) {
		goto out;
	}

	sshbuf_reset(buf);

#ifdef DEBUG_KEXECDH
	fputs("public key:\n", stderr);
	EVP_PKEY_print_public_fp(stderr, pub_key, 8, NULL);
#endif

#if 0 // TODO?
	if (sshkey_ec_validate_public(group, dh_pub) != 0) {
		r = SSH_ERR_MESSAGE_INCOMPLETE;
		goto out;
	}
#endif

	r = derive_secret(pkey, pub_key, buf);
	if (r != 0) {
		goto out;
	}

	*shared_secretp = buf;
	buf = NULL;

 out:
	EVP_PKEY_free(pub_key);
	sshbuf_free(buf);
	return r;
}

int
kex_ecdh_enc(struct kex *kex, const struct sshbuf *client_blob,
    struct sshbuf **server_blobp, struct sshbuf **shared_secretp)
{
	EVP_PKEY *server_key = NULL;
	struct sshbuf *server_blob = NULL;
	struct sshbuf *shared_secret = NULL;
	int r;

	*server_blobp = NULL;
	*shared_secretp = NULL;

	if ((r = generate_ec_pkey_from_nid(kex->ec_nid, &server_key)) != 0) {
		goto out;
	}

#ifdef DEBUG_KEXECDH
	fputs("server private key:\n", stderr);
	EVP_PKEY_print_private_fp(stderr, server_key, 8, NULL);
#endif

	if ((server_blob = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if ((r = sshbuf_put_evp_pkey_ec(server_blob, server_key, 0)) != 0) {
		goto out;
	}

	if ((r = sshbuf_get_u32(server_blob, NULL)) != 0)
		goto out;

	if ((r = kex_ecdh_dec_key(kex, client_blob, server_key, &shared_secret)) != 0)
		goto out;

	*server_blobp = server_blob;
	server_blob = NULL;
	*shared_secretp = shared_secret;
	shared_secret = NULL;

	r = 0;
out:
	EVP_PKEY_free(server_key);
	sshbuf_free(server_blob);
	sshbuf_free(shared_secret);
	return r;
}

int
kex_ecdh_dec(struct kex *kex, const struct sshbuf *server_blob,
    struct sshbuf **shared_secretp)
{
	int r;

	r = kex_ecdh_dec_key(kex, server_blob, kex->ec_client_key, shared_secretp);
	EVP_PKEY_free(kex->ec_client_key);
	kex->ec_client_key = NULL;
	return r;
}
#else
static int
kex_ecdh_dec_key_group(struct kex *, const struct sshbuf *, EC_KEY *key,
    const EC_GROUP *, struct sshbuf **);

int
kex_ecdh_keypair(struct kex *kex)
{
	EC_KEY *client_key = NULL;
	const EC_GROUP *group;
	const EC_POINT *public_key;
	struct sshbuf *buf = NULL;
	int r;

	if ((client_key = EC_KEY_new_by_curve_name(kex->ec_nid)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (EC_KEY_generate_key(client_key) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	group = EC_KEY_get0_group(client_key);
	public_key = EC_KEY_get0_public_key(client_key);

	if ((buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_put_ec(buf, public_key, group)) != 0 ||
	    (r = sshbuf_get_u32(buf, NULL)) != 0)
		goto out;
#ifdef DEBUG_KEXECDH
	fputs("client private key:\n", stderr);
	sshkey_dump_ec_key(client_key);
#endif
	kex->ec_client_key = client_key;
	kex->ec_group = group;
	client_key = NULL;	/* owned by the kex */
	kex->client_pub = buf;
	buf = NULL;
 out:
	EC_KEY_free(client_key);
	sshbuf_free(buf);
	return r;
}

int
kex_ecdh_enc(struct kex *kex, const struct sshbuf *client_blob,
    struct sshbuf **server_blobp, struct sshbuf **shared_secretp)
{
	const EC_GROUP *group;
	const EC_POINT *pub_key;
	EC_KEY *server_key = NULL;
	struct sshbuf *server_blob = NULL;
	int r;

	*server_blobp = NULL;
	*shared_secretp = NULL;

	if ((server_key = EC_KEY_new_by_curve_name(kex->ec_nid)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (EC_KEY_generate_key(server_key) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	group = EC_KEY_get0_group(server_key);

#ifdef DEBUG_KEXECDH
	fputs("server private key:\n", stderr);
	sshkey_dump_ec_key(server_key);
#endif
	pub_key = EC_KEY_get0_public_key(server_key);
	if ((server_blob = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_put_ec(server_blob, pub_key, group)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, NULL)) != 0)
		goto out;
	if ((r = kex_ecdh_dec_key_group(kex, client_blob, server_key, group,
	    shared_secretp)) != 0)
		goto out;
	*server_blobp = server_blob;
	server_blob = NULL;
 out:
	EC_KEY_free(server_key);
	sshbuf_free(server_blob);
	return r;
}

static int
kex_ecdh_dec_key_group(struct kex *kex, const struct sshbuf *ec_blob,
    EC_KEY *key, const EC_GROUP *group, struct sshbuf **shared_secretp)
{
	struct sshbuf *buf = NULL;
	BIGNUM *shared_secret = NULL;
	EC_POINT *dh_pub = NULL;
	u_char *kbuf = NULL;
	size_t klen = 0;
	int r;

	*shared_secretp = NULL;

	if ((buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_put_stringb(buf, ec_blob)) != 0)
		goto out;
	if ((dh_pub = EC_POINT_new(group)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_get_ec(buf, dh_pub, group)) != 0) {
		goto out;
	}
	sshbuf_reset(buf);

#ifdef DEBUG_KEXECDH
	fputs("public key:\n", stderr);
	sshkey_dump_ec_point(group, dh_pub);
#endif
	if (sshkey_ec_validate_public(group, dh_pub) != 0) {
		r = SSH_ERR_MESSAGE_INCOMPLETE;
		goto out;
	}
	klen = (EC_GROUP_get_degree(group) + 7) / 8;
	if ((kbuf = malloc(klen)) == NULL ||
	    (shared_secret = BN_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (ECDH_compute_key(kbuf, klen, dh_pub, key, NULL) != (int)klen ||
	    BN_bin2bn(kbuf, klen, shared_secret) == NULL) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
#ifdef DEBUG_KEXECDH
	dump_digest("shared secret", kbuf, klen);
#endif
	if ((r = sshbuf_put_bignum2(buf, shared_secret)) != 0)
		goto out;
	*shared_secretp = buf;
	buf = NULL;
 out:
	EC_POINT_clear_free(dh_pub);
	BN_clear_free(shared_secret);
	freezero(kbuf, klen);
	sshbuf_free(buf);
	return r;
}

int
kex_ecdh_dec(struct kex *kex, const struct sshbuf *server_blob,
    struct sshbuf **shared_secretp)
{
	int r;

	r = kex_ecdh_dec_key_group(kex, server_blob, kex->ec_client_key,
	    kex->ec_group, shared_secretp);
	EC_KEY_free(kex->ec_client_key);
	kex->ec_client_key = NULL;
	return r;
}

#endif /* OPENSSL_VERSION_NUMBER >= 0x3000000L */
#else

#include "ssherr.h"

struct kex;
struct sshbuf;
struct sshkey;

int
kex_ecdh_keypair(struct kex *kex)
{
	return SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

int
kex_ecdh_enc(struct kex *kex, const struct sshbuf *client_blob,
    struct sshbuf **server_blobp, struct sshbuf **shared_secretp)
{
	return SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

int
kex_ecdh_dec(struct kex *kex, const struct sshbuf *server_blob,
    struct sshbuf **shared_secretp)
{
	return SSH_ERR_SIGN_ALG_UNSUPPORTED;
}
#endif /* defined(WITH_OPENSSL) && defined(OPENSSL_HAS_ECC) */
