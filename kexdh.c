/* $OpenBSD: kexdh.c,v 1.35 2025/10/03 00:08:02 djm Exp $ */
/*
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

#ifdef WITH_OPENSSL

#include <sys/types.h>

#include <stdio.h>
#include <string.h>
#include <signal.h>

#include "openbsd-compat/openssl-compat.h"
#include <openssl/bn.h>
#include <openssl/dh.h>

#include "sshkey.h"
#include "kex.h"
#include "sshbuf.h"
#include "digest.h"
#include "ssherr.h"
#include "dh.h"
#include "log.h"

int
kex_dh_keygen(struct kex *kex)
{
	switch (kex->kex_type) {
	case KEX_DH_GRP1_SHA1:
		kex->dh = dh_new_group1();
		break;
	case KEX_DH_GRP14_SHA1:
	case KEX_DH_GRP14_SHA256:
		kex->dh = dh_new_group14();
		break;
	case KEX_DH_GRP16_SHA512:
		kex->dh = dh_new_group16();
		break;
	case KEX_DH_GRP18_SHA512:
		kex->dh = dh_new_group18();
		break;
	default:
		return SSH_ERR_INVALID_ARGUMENT;
	}
	if (kex->dh == NULL)
		return SSH_ERR_ALLOC_FAIL;
	return (dh_gen_key(kex->dh, kex->we_need * 8));
}

int
kex_dh_compute_key(struct kex *kex, BIGNUM *dh_pub, struct sshbuf *out)
{
	BIGNUM *shared_secret = NULL;
	int r;

#ifdef DEBUG_KEXDH
	fprintf(stderr, "dh_pub= ");
	BN_print_fp(stderr, dh_pub);
	fprintf(stderr, "\n");
	debug("bits %d", BN_num_bits(dh_pub));
#if WITH_OPENSSL_V3
	EVP_PKEY_print_params_fp(stderr, kex->dh->params, 8, NULL);
#else
	DHparams_print_fp(stderr, kex->dh);
#endif
	fprintf(stderr, "\n");
#endif

	if ((r = dh_compute_key(kex->dh, dh_pub, &shared_secret)) != 0) {
		goto out;
	}

	r = sshbuf_put_bignum2(out, shared_secret);
 out:
	BN_clear_free(shared_secret);
	return r;
}

int
kex_dh_keypair(struct kex *kex)
{
	BIGNUM *pub_key = NULL;
	struct sshbuf *buf = NULL;
	int r;

	if ((r = kex_dh_keygen(kex)) != 0)
		return r;
	if ((r = ssh_dh_key_get_pub(kex->dh, &pub_key)) != 0)
		return r;
	if ((buf = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = sshbuf_put_bignum2(buf, pub_key)) != 0 ||
	    (r = sshbuf_get_u32(buf, NULL)) != 0)
		goto out;
#ifdef DEBUG_KEXDH
#if WITH_OPENSSL_V3
	EVP_PKEY_print_params_fp(stderr, kex->dh->params, 8, NULL);
#else
	DHparams_print_fp(stderr, kex->dh);
#endif
	fprintf(stderr, "pub= ");
	BN_print_fp(stderr, pub_key);
	fprintf(stderr, "\n");
#endif
	kex->client_pub = buf;
	buf = NULL;
 out:
	BN_clear_free(pub_key);
	sshbuf_free(buf);
	return r;
}

int
kex_dh_enc(struct kex *kex, const struct sshbuf *client_blob,
    struct sshbuf **server_blobp, struct sshbuf **shared_secretp)
{
	BIGNUM *pub_key = NULL;
	struct sshbuf *server_blob = NULL;
	int r;

	*server_blobp = NULL;
	*shared_secretp = NULL;

	if ((r = kex_dh_keygen(kex)) != 0)
		goto out;
	if ((r = ssh_dh_key_get_pub(kex->dh, &pub_key)) != 0)
		goto out;
	if ((server_blob = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_put_bignum2(server_blob, pub_key)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, NULL)) != 0)
		goto out;
	if ((r = kex_dh_dec(kex, client_blob, shared_secretp)) != 0)
		goto out;
	*server_blobp = server_blob;
	server_blob = NULL;
 out:
	BN_clear_free(pub_key);
	dh_free(kex->dh);
	kex->dh = NULL;
	sshbuf_free(server_blob);
	return r;
}

int
kex_dh_dec(struct kex *kex, const struct sshbuf *dh_blob,
    struct sshbuf **shared_secretp)
{
	struct sshbuf *buf = NULL;
	BIGNUM *dh_pub = NULL;
	int r;

	*shared_secretp = NULL;

	if ((buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_put_stringb(buf, dh_blob)) != 0 ||
	    (r = sshbuf_get_bignum2(buf, &dh_pub)) != 0)
		goto out;
	sshbuf_reset(buf);
	if ((r = kex_dh_compute_key(kex, dh_pub, buf)) != 0)
		goto out;
	*shared_secretp = buf;
	buf = NULL;
 out:
	BN_free(dh_pub);
	dh_free(kex->dh);
	kex->dh = NULL;
	sshbuf_free(buf);
	return r;
}
#endif /* WITH_OPENSSL */
