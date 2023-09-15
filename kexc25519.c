/* $OpenBSD: kexc25519.c,v 1.18 2024/09/02 12:13:56 djm Exp $ */
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

#ifdef ENABLE_NONFIPS
#if defined(WITH_OPENSSL) && WITH_OPENSSL_V3

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include "osslv3.h"

int
kexc25519_keygen(EVP_PKEY **pkeyp, u_char pub[CURVE25519_SIZE])
{
	int r = SSH_ERR_LIBCRYPTO_ERROR;
	EVP_PKEY *pkey = NULL;
	size_t keysize = 0;

	if ((pkey = EVP_PKEY_Q_keygen(NULL, NULL, SN_X25519)) == NULL)
		goto out;
	if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, pub, CURVE25519_SIZE, &keysize) != 1)
		goto out;
	if (keysize != CURVE25519_SIZE) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	/* success */
	*pkeyp = pkey;
	pkey = NULL;
	r = 0;
 out:
	EVP_PKEY_free(pkey);
	return r;
}

int
kex_c25519_keypair(struct kex *kex)
{
	struct sshbuf *buf = NULL;
	u_char *cp = NULL;
	EVP_PKEY *client_key = NULL;
	int r;

	if ((buf = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = sshbuf_reserve(buf, CURVE25519_SIZE, &cp)) != 0)
		goto out;
	if ((r = kexc25519_keygen(&client_key, cp)) != 0)
		goto out;

#ifdef DEBUG_KEXECDH
	fputs("c25519 client private key:\n", stderr);
	EVP_PKEY_print_private_fp(stderr, client_key, 8, NULL);
#endif /* DEBUG_KEXECDH */

	kex->client_pkey = client_key;
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
make_c25519_pkey_from_pub_key_bytes(const u_char *pub_key, EVP_PKEY **pkeyp)
{
	EVP_PKEY_CTX *ctx = NULL;
	OSSL_PARAM param[2];
	int r = SSH_ERR_LIBCRYPTO_ERROR;

	ctx = EVP_PKEY_CTX_new_from_name(NULL, SN_X25519, NULL);
	if (ctx == NULL)
		goto out;

	if (EVP_PKEY_fromdata_init(ctx) != 1)
		goto out;

	param[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void *)pub_key, CURVE25519_SIZE);
	param[1] = OSSL_PARAM_construct_end();
	if (EVP_PKEY_fromdata(ctx, pkeyp, EVP_PKEY_PUBLIC_KEY, param) != 1)
		goto out;

	r = 0;

 out:
	EVP_PKEY_CTX_free(ctx);
	return r;
}

static int
derive_secret(EVP_PKEY *host_key, EVP_PKEY *pub_key, struct sshbuf *shared_secret)
{
	EVP_PKEY_CTX *ctx = NULL;
	int r = SSH_ERR_LIBCRYPTO_ERROR;
	u_char *ss = NULL;
	size_t sslen = 0;

	if ((ctx = EVP_PKEY_CTX_new_from_pkey(NULL, host_key, NULL)) == NULL)
		goto out;

	if (EVP_PKEY_derive_init(ctx) != 1)
		goto out;

	if (EVP_PKEY_derive_set_peer(ctx, pub_key) != 1)
		goto out;

	if (EVP_PKEY_derive(ctx, NULL, &sslen) != 1)
		goto out;

	if ((r = sshbuf_reserve(shared_secret, sslen, &ss)) != 0) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if (EVP_PKEY_derive(ctx, ss, &sslen) != 1)
		goto out;

#ifdef DEBUG_KEXECDH
	dump_digest("c25519 shared secret", ss, sslen);
#endif

	r = 0;

out:
	EVP_PKEY_CTX_free(ctx);
	return r;
}

int
kexc25519_shared_key_ext(EVP_PKEY *pkey,
    const u_char pub[CURVE25519_SIZE], struct sshbuf *out, int raw)
{
	struct sshbuf *shared_key = NULL;
	u_char zero[CURVE25519_SIZE];
	int r;
	EVP_PKEY *pub_pkey = NULL;

	if ((r = make_c25519_pkey_from_pub_key_bytes(pub, &pub_pkey)) != 0)
		goto out;

	if ((shared_key = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if ((r = derive_secret(pkey, pub_pkey, shared_key)) != 0)
		goto out;

	/* Check for all-zero shared secret */
	explicit_bzero(zero, CURVE25519_SIZE);
	if (timingsafe_bcmp(zero, sshbuf_ptr(shared_key), CURVE25519_SIZE) == 0) {
		r = SSH_ERR_KEY_INVALID_EC_VALUE;
		goto out;
	}

#ifdef DEBUG_KEXECDH
	fprintf(stderr, "shared secret\n");
	sshbuf_dump(shared_key, stderr);
#endif
	if (raw)
		r = sshbuf_put(out, sshbuf_ptr(shared_key), CURVE25519_SIZE);
	else
		r = sshbuf_put_bignum2_bytes(out, sshbuf_ptr(shared_key), CURVE25519_SIZE);
 out:
	sshbuf_free(shared_key);
	EVP_PKEY_free(pub_pkey);
	return r;
}

int
kexc25519_shared_key(EVP_PKEY *pkey, const u_char pub[CURVE25519_SIZE], struct sshbuf *out)
{
	return kexc25519_shared_key_ext(pkey, pub, out, 0);
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
	dump_digest("shared secret 25519", shared_key, CURVE25519_SIZE);
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

#endif /* defined(WITH_OPENSSL) && WITH_OPENSSL_V3 */

int
kex_c25519_enc(struct kex *kex, const struct sshbuf *client_blob,
   struct sshbuf **server_blobp, struct sshbuf **shared_secretp)
{
	struct sshbuf *server_blob = NULL;
	struct sshbuf *buf = NULL;
	const u_char *client_pub;
	u_char *server_pub;
#if WITH_OPENSSL_V3
	EVP_PKEY *server_pkey = NULL;
#else
	u_char server_key[CURVE25519_SIZE];
#endif /* WITH_OPENSSL_V3 */
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
#if WITH_OPENSSL_V3
	if ((r = kexc25519_keygen(&server_pkey, server_pub)) != 0)
		goto out;
#else
	kexc25519_keygen(server_key, server_pub);
#endif
	/* allocate shared secret */
	if ((buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
#if WITH_OPENSSL_V3
	if ((r = kexc25519_shared_key_ext(server_pkey, client_pub, buf, 0)) < 0)
		goto out;
#else
	if ((r = kexc25519_shared_key_ext(server_key, client_pub, buf, 0)) < 0)
		goto out;
#endif
#ifdef DEBUG_KEXECDH
	dump_digest("server public key 25519:", server_pub, CURVE25519_SIZE);
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = NULL;
	buf = NULL;
 out:
#if WITH_OPENSSL_V3
	EVP_PKEY_free(server_pkey);
#else
	explicit_bzero(server_key, sizeof(server_key));
#endif /* WITH_OPENSSL_V3 */
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
#if WITH_OPENSSL_V3
	if ((r = kexc25519_shared_key_ext(kex->client_pkey, server_pub,
	    buf, 0)) < 0)
		goto out;
#else
	if ((r = kexc25519_shared_key_ext(kex->c25519_client_key, server_pub,
	    buf, 0)) < 0)
		goto out;
#endif
#ifdef DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	*shared_secretp = buf;
	buf = NULL;
 out:
	sshbuf_free(buf);
	return r;
}

#endif /* ENABLE_NONFIPS */
