/* $OpenBSD: kexc25519.c,v 1.17 2019/01/21 10:40:11 djm Exp $ */
/*
 * Copyright (c) 2019 Markus Friedl.  All rights reserved.
 * Copyright (c) 2010 Damien Miller.  All rights reserved.
 * Copyright (c) 2013 Aris Adamantiadis.  All rights reserved.
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

#include <sys/types.h>

#include <stdio.h>
#include <string.h>
#include <signal.h>

#include "sshkey.h"
#include "kex.h"
#include "sshbuf.h"
#include "digest.h"
#include "ssherr.h"
#include "ssh2.h"

#ifdef DISABLE_NONFIPS

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

static int
kexc25519_keygen(EVP_PKEY **pkeyp)
{
	EVP_PKEY *pkey = NULL;

	if ((pkey = EVP_PKEY_Q_keygen(NULL, NULL, SN_X25519)) == NULL) {
		return SSH_ERR_LIBCRYPTO_ERROR;
	}

	*pkeyp = pkey;
	return 0;
}

int
kex_c25519_keypair(struct kex *kex)
{
	struct sshbuf *buf = NULL;
	u_char *cp = NULL;
	EVP_PKEY *client_key = NULL;
	int r;
	size_t keysize = 0;

	if ((buf = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;

	if ((r = kexc25519_keygen(&client_key)) != 0)
		goto out;

	if ((r = sshbuf_reserve(buf, CURVE25519_SIZE, &cp)) != 0)
		goto out;

	if (EVP_PKEY_get_octet_string_param(client_key, OSSL_PKEY_PARAM_PUB_KEY, cp, CURVE25519_SIZE, &keysize) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	if (keysize != CURVE25519_SIZE) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

#ifdef DEBUG_KEXECDH
	fputs("c25519 client private key:\n", stderr);
	EVP_PKEY_print_private_fp(stdout, pkey, 8, NULL);
#endif /* DEBUG_KEXECDH */

	kex->ec_client_key = client_key;
	client_key = NULL;
	kex->client_pub = buf;
	buf = NULL;
	r = 0;
 out:
	EVP_PKEY_free(client_key);
	sshbuf_free(buf);
	return r;
}

static int
make_evp_pkey_from_c25519_pub_key_bytes(
	const unsigned char *pub_key_bytes, size_t pub_key_len,
	EVP_PKEY **pkeyp)
{
	EVP_PKEY_CTX *ctx = NULL;
	OSSL_PARAM_BLD *param_bld = NULL;
	OSSL_PARAM *param = NULL;
	int r = SSH_ERR_LIBCRYPTO_ERROR;

	ctx = EVP_PKEY_CTX_new_from_name(NULL, SN_X25519, NULL);
	if (ctx == NULL) {
		goto out;
	}

	if (EVP_PKEY_fromdata_init(ctx) != 1) {
		goto out;
	}

	if ((param_bld = OSSL_PARAM_BLD_new()) == NULL) {
		goto out;
	}

	if (OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_PUB_KEY, pub_key_bytes, pub_key_len) != 1) {
		goto out;
	}

	if ((param = OSSL_PARAM_BLD_to_param(param_bld)) == NULL) {
		goto out;
	}

	if (EVP_PKEY_fromdata(ctx, pkeyp, EVP_PKEY_PUBLIC_KEY, param) != 1) {
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
	dump_digest("c25519 shared secret", ss, sslen);
#endif

	r = sshbuf_put_bignum2_bytes(shared_secret, ss, sslen);

out:
	freezero(ss, sslen);
	EVP_PKEY_CTX_free(ctx);
	return r;
}

static int
kex_c25519_dec_key(struct kex *kex, const struct sshbuf *key_blob,
    EVP_PKEY *pkey, struct sshbuf **shared_secretp)
{
	struct sshbuf *buf = NULL;
	int r;
	EVP_PKEY *pub_key = NULL;

	*shared_secretp = NULL;

	if (sshbuf_len(key_blob) != CURVE25519_SIZE) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}

	r = make_evp_pkey_from_c25519_pub_key_bytes(sshbuf_ptr(key_blob), sshbuf_len(key_blob), &pub_key);
	if (r != 0) {
		goto out;
	}

#ifdef DEBUG_KEXECDH
	fputs("c25519 public key:\n", stderr);
	EVP_PKEY_print_public_fp(stderr, pub_key, 8, NULL);
#endif

	/* shared secret */
	if ((buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if ((r = derive_secret(pkey, pub_key, buf)) != 0) {
		goto out;
	}

	*shared_secretp = buf;
	buf = NULL;

 out:
	EVP_PKEY_free(pub_key);
	sshbuf_free(buf);
	return r;
}

static int
sshbuf_put_evp_pkey_c25519(struct sshbuf *b, EVP_PKEY *pkey)
{
	int r;
	size_t size = 0;
	size_t len = 0;
	u_char *cp = NULL;

	if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &size) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	if ((r = sshbuf_reserve(b, size, &cp)) != 0) {
		goto out;
	}

	if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, cp, size, &len) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	r = 0;
out:
	return r;
}

int
kex_c25519_enc(struct kex *kex, const struct sshbuf *client_blob,
   struct sshbuf **server_blobp, struct sshbuf **shared_secretp)
{
	EVP_PKEY *server_key = NULL;
	struct sshbuf *server_blob = NULL;
	struct sshbuf *shared_secret = NULL;
	int r;

	*server_blobp = NULL;
	*shared_secretp = NULL;

	if (sshbuf_len(client_blob) != CURVE25519_SIZE) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}

	if ((r = kexc25519_keygen(&server_key)) != 0) {
		goto out;
	}

#ifdef DEBUG_KEXECDH
	fputs("c25519 server private key:\n", stderr);
	EVP_PKEY_print_private_fp(stderr, server_key, 8, NULL);
#endif

	/* allocate space for encrypted KEM key and ECDH pub key */
	if ((server_blob = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if ((r = sshbuf_put_evp_pkey_c25519(server_blob, server_key)) != 0) {
		goto out;
	}

#ifdef DEBUG_KEXECDH
	dump_digest("client public key 25519:", sshbuf_ptr(client_blob), sshbuf_len(client_blob));
#endif

	if ((r = kex_c25519_dec_key(kex, client_blob, server_key, &shared_secret)) != 0) {
		goto out;
	}

#ifdef DEBUG_KEXECDH
	dump_digest("server public key 25519:", server_pub, CURVE25519_SIZE);
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	*server_blobp = server_blob;
	*shared_secretp = shared_secret;
	server_blob = NULL;
	shared_secret = NULL;
 out:
	EVP_PKEY_free(server_key);
	sshbuf_free(server_blob);
	sshbuf_free(shared_secret);
	return r;
}

int
kex_c25519_dec(struct kex *kex, const struct sshbuf *server_blob,
    struct sshbuf **shared_secretp)
{
	int r;

	r = kex_c25519_dec_key(kex, server_blob, kex->ec_client_key, shared_secretp);
	EVP_PKEY_free(kex->ec_client_key);
	kex->ec_client_key = NULL;
	return r;
}

#else

extern int crypto_scalarmult_curve25519(u_char a[CURVE25519_SIZE],
    const u_char b[CURVE25519_SIZE], const u_char c[CURVE25519_SIZE])
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 3, CURVE25519_SIZE)));

void
kexc25519_keygen(u_char key[CURVE25519_SIZE], u_char pub[CURVE25519_SIZE])
{
	static const u_char basepoint[CURVE25519_SIZE] = {9};

	arc4random_buf(key, CURVE25519_SIZE);
	crypto_scalarmult_curve25519(pub, key, basepoint);
}

int
kexc25519_shared_key_ext(const u_char key[CURVE25519_SIZE],
    const u_char pub[CURVE25519_SIZE], struct sshbuf *out, int raw)
{
	u_char shared_key[CURVE25519_SIZE];
	u_char zero[CURVE25519_SIZE];
	int r;

	crypto_scalarmult_curve25519(shared_key, key, pub);

	/* Check for all-zero shared secret */
	explicit_bzero(zero, CURVE25519_SIZE);
	if (timingsafe_bcmp(zero, shared_key, CURVE25519_SIZE) == 0)
		return SSH_ERR_KEY_INVALID_EC_VALUE;

#ifdef DEBUG_KEXECDH
	dump_digest("shared secret", shared_key, CURVE25519_SIZE);
#endif
	if (raw)
		r = sshbuf_put(out, shared_key, CURVE25519_SIZE);
	else
		r = sshbuf_put_bignum2_bytes(out, shared_key, CURVE25519_SIZE);
	explicit_bzero(shared_key, CURVE25519_SIZE);
	return r;
}

int
kexc25519_shared_key(const u_char key[CURVE25519_SIZE],
    const u_char pub[CURVE25519_SIZE], struct sshbuf *out)
{
	return kexc25519_shared_key_ext(key, pub, out, 0);
}

int
kex_c25519_keypair(struct kex *kex)
{
	struct sshbuf *buf = NULL;
	u_char *cp = NULL;
	int r;

	if ((buf = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = sshbuf_reserve(buf, CURVE25519_SIZE, &cp)) != 0)
		goto out;
	kexc25519_keygen(kex->c25519_client_key, cp);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key c25519:", cp, CURVE25519_SIZE);
#endif
	kex->client_pub = buf;
	buf = NULL;
 out:
	sshbuf_free(buf);
	return r;
}

int
kex_c25519_enc(struct kex *kex, const struct sshbuf *client_blob,
   struct sshbuf **server_blobp, struct sshbuf **shared_secretp)
{
	struct sshbuf *server_blob = NULL;
	struct sshbuf *buf = NULL;
	const u_char *client_pub;
	u_char *server_pub;
	u_char server_key[CURVE25519_SIZE];
	int r;

	*server_blobp = NULL;
	*shared_secretp = NULL;

	if (sshbuf_len(client_blob) != CURVE25519_SIZE) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
	client_pub = sshbuf_ptr(client_blob);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key 25519:", client_pub, CURVE25519_SIZE);
#endif
	/* allocate space for encrypted KEM key and ECDH pub key */
	if ((server_blob = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_reserve(server_blob, CURVE25519_SIZE, &server_pub)) != 0)
		goto out;
	kexc25519_keygen(server_key, server_pub);
	/* allocate shared secret */
	if ((buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = kexc25519_shared_key_ext(server_key, client_pub, buf, 0)) < 0)
		goto out;
#ifdef DEBUG_KEXECDH
	dump_digest("server public key 25519:", server_pub, CURVE25519_SIZE);
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = NULL;
	buf = NULL;
 out:
	explicit_bzero(server_key, sizeof(server_key));
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	return r;
}

int
kex_c25519_dec(struct kex *kex, const struct sshbuf *server_blob,
    struct sshbuf **shared_secretp)
{
	struct sshbuf *buf = NULL;
	const u_char *server_pub;
	int r;

	*shared_secretp = NULL;

	if (sshbuf_len(server_blob) != CURVE25519_SIZE) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
	server_pub = sshbuf_ptr(server_blob);
#ifdef DEBUG_KEXECDH
	dump_digest("server public key c25519:", server_pub, CURVE25519_SIZE);
#endif
	/* shared secret */
	if ((buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = kexc25519_shared_key_ext(kex->c25519_client_key, server_pub,
	    buf, 0)) < 0)
		goto out;
#ifdef DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	*shared_secretp = buf;
	buf = NULL;
 out:
	sshbuf_free(buf);
	return r;
}

#endif /* DISABLE_NONFIPS */
