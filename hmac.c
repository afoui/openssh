/* $OpenBSD: hmac.c,v 1.15 2025/09/05 09:49:26 dtucker Exp $ */
/*
 * Copyright (c) 2014 Markus Friedl.  All rights reserved.
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

#include <sys/types.h>

#include <stdlib.h>
#include <string.h>

#if WITH_OPENSSL_V3
#include <openssl/core_names.h>
#endif /* WITH_OPENSSL_V3 */

#include "sshbuf.h"
#include "ssherr.h"
#include "digest.h"
#include "hmac.h"

struct ssh_hmac_ctx {
	int			 alg;
#if WITH_OPENSSL_V3
	EVP_MAC			*mac;
	EVP_MAC_CTX		*ctx;
#else
	struct ssh_digest_ctx	*ictx;
	struct ssh_digest_ctx	*octx;
	struct ssh_digest_ctx	*digest;
	u_char			*buf;
	size_t			 buf_len;
#endif /* WITH_OPENSSL_V3 */
};

size_t
ssh_hmac_bytes(int alg)
{
	return ssh_digest_bytes(alg);
}

#if WITH_OPENSSL_V3
/* NB. Indexed directly by algorithm number (SSH_DIGEST_XXX) */
static const char *
alg_names[] = {
	SN_md5,
	SN_sha1,
	SN_sha256,
	SN_sha384,
	SN_sha512,
};
#endif /* WITH_OPENSSL_V3 */

struct ssh_hmac_ctx *
ssh_hmac_start(int alg)
{
#if WITH_OPENSSL_V3
	struct ssh_hmac_ctx *ret;

	if ((ret = calloc(1, sizeof(*ret))) == NULL)
		goto fail;
	ret->alg = alg;
	if ((ret->mac = EVP_MAC_fetch(NULL, SN_hmac, NULL)) == NULL)
		goto fail;
	if ((ret->ctx = EVP_MAC_CTX_new(ret->mac)) == NULL)
		goto fail;
	return ret;
 fail:
	ssh_hmac_free(ret);
	return NULL;
#else
	struct ssh_hmac_ctx	*ret;

	if ((ret = calloc(1, sizeof(*ret))) == NULL)
		return NULL;
	ret->alg = alg;
	if ((ret->ictx = ssh_digest_start(alg)) == NULL ||
	    (ret->octx = ssh_digest_start(alg)) == NULL ||
	    (ret->digest = ssh_digest_start(alg)) == NULL)
		goto fail;
	ret->buf_len = ssh_digest_blocksize(ret->ictx);
	if ((ret->buf = calloc(1, ret->buf_len)) == NULL)
		goto fail;
	return ret;
fail:
	ssh_hmac_free(ret);
	return NULL;
#endif /* WITH_OPENSSL_V3 */
}

int
ssh_hmac_init(struct ssh_hmac_ctx *ctx, const void *key, size_t klen)
{
#if WITH_OPENSSL_V3
	OSSL_PARAM params[2];
	const char *alg_name;

	if (ctx->alg < 0 || ctx->alg >= SSH_DIGEST_MAX)
		return -1;
	alg_name = alg_names[ctx->alg];
	params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char *)alg_name, 0);
	params[1] = OSSL_PARAM_construct_end();
	if (EVP_MAC_init(ctx->ctx, (const unsigned char *)key, klen, params) != 1)
		return -1;
	return 0;
#else
	size_t i;

	/* reset ictx and octx if no is key given */
	if (key != NULL) {
		/* truncate long keys */
		if (klen <= ctx->buf_len)
			memcpy(ctx->buf, key, klen);
		else if (ssh_digest_memory(ctx->alg, key, klen, ctx->buf,
		    ctx->buf_len) < 0)
			return -1;
		for (i = 0; i < ctx->buf_len; i++)
			ctx->buf[i] ^= 0x36;
		if (ssh_digest_update(ctx->ictx, ctx->buf, ctx->buf_len) < 0)
			return -1;
		for (i = 0; i < ctx->buf_len; i++)
			ctx->buf[i] ^= 0x36 ^ 0x5c;
		if (ssh_digest_update(ctx->octx, ctx->buf, ctx->buf_len) < 0)
			return -1;
		explicit_bzero(ctx->buf, ctx->buf_len);
	}
	/* start with ictx */
	if (ssh_digest_copy_state(ctx->ictx, ctx->digest) < 0)
		return -1;
	return 0;
#endif /* WITH_OPENSSL_V3 */
}

int
ssh_hmac_update(struct ssh_hmac_ctx *ctx, const void *m, size_t mlen)
{
#if WITH_OPENSSL_V3
	if (EVP_MAC_update(ctx->ctx, (const unsigned char *)m, mlen) != 1)
		return SSH_ERR_LIBCRYPTO_ERROR;
	return 0;
#else
	return ssh_digest_update(ctx->digest, m, mlen);
#endif /* WITH_OPENSSL_V3 */
}

int
ssh_hmac_update_buffer(struct ssh_hmac_ctx *ctx, const struct sshbuf *b)
{
#if WITH_OPENSSL_V3
	if (EVP_MAC_update(ctx->ctx, sshbuf_ptr(b), sshbuf_len(b)) != 1)
		return SSH_ERR_LIBCRYPTO_ERROR;
	return 0;
#else
	return ssh_digest_update_buffer(ctx->digest, b);
#endif /* WITH_OPENSSL_V3 */
}

int
ssh_hmac_final(struct ssh_hmac_ctx *ctx, u_char *d, size_t dlen)
{
	size_t len;

#if WITH_OPENSSL_V3
	if (EVP_MAC_final(ctx->ctx, d, &len, dlen) != 1)
		return 1;
	return 0;
#else
	len = ssh_digest_bytes(ctx->alg);
	if (dlen < len ||
	    ssh_digest_final(ctx->digest, ctx->buf, len))
		return -1;
	/* switch to octx */
	if (ssh_digest_copy_state(ctx->octx, ctx->digest) < 0 ||
	    ssh_digest_update(ctx->digest, ctx->buf, len) < 0 ||
	    ssh_digest_final(ctx->digest, d, dlen) < 0)
		return -1;
	return 0;
#endif /* WITH_OPENSSL_V3 */
}

void
ssh_hmac_free(struct ssh_hmac_ctx *ctx)
{
	if (ctx != NULL) {
#if WITH_OPENSSL_V3
		EVP_MAC_CTX_free(ctx->ctx);
		EVP_MAC_free(ctx->mac);
#else
		ssh_digest_free(ctx->ictx);
		ssh_digest_free(ctx->octx);
		ssh_digest_free(ctx->digest);
		if (ctx->buf) {
			explicit_bzero(ctx->buf, ctx->buf_len);
			free(ctx->buf);
		}
#endif /* WITH_OPENSSL_V3 */
		freezero(ctx, sizeof(*ctx));
	}
}

#ifdef TEST

/* cc -DTEST hmac.c digest.c buffer.c cleanup.c fatal.c log.c xmalloc.c -lcrypto */
static void
hmac_test(void *key, size_t klen, void *m, size_t mlen, u_char *e, size_t elen)
{
	struct ssh_hmac_ctx	*ctx;
	size_t			 i;
	u_char			 digest[16];

	if ((ctx = ssh_hmac_start(SSH_DIGEST_MD5)) == NULL)
		printf("ssh_hmac_start failed");
	if (ssh_hmac_init(ctx, key, klen) < 0 ||
	    ssh_hmac_update(ctx, m, mlen) < 0 ||
	    ssh_hmac_final(ctx, digest, sizeof(digest)) < 0)
		printf("ssh_hmac_xxx failed");
	ssh_hmac_free(ctx);

	if (memcmp(e, digest, elen)) {
		for (i = 0; i < elen; i++)
			printf("[%zu] %2.2x %2.2x\n", i, e[i], digest[i]);
		printf("mismatch\n");
	} else
		printf("ok\n");
}

int
main(int argc, char **argv)
{
	/* try test vectors from RFC 2104 */

	u_char key1[16] = {
	    0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb,
	    0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb };
	u_char *data1 = "Hi There";
	u_char dig1[16] = {
	    0x92, 0x94, 0x72, 0x7a, 0x36, 0x38, 0xbb, 0x1c,
	    0x13, 0xf4, 0x8e, 0xf8, 0x15, 0x8b, 0xfc, 0x9d };

	u_char *key2 = "Jefe";
	u_char *data2 = "what do ya want for nothing?";
	u_char dig2[16] = {
	    0x75, 0x0c, 0x78, 0x3e, 0x6a, 0xb0, 0xb5, 0x03,
	    0xea, 0xa8, 0x6e, 0x31, 0x0a, 0x5d, 0xb7, 0x38 };

	u_char key3[16];
	u_char data3[50];
	u_char dig3[16] = {
	    0x56, 0xbe, 0x34, 0x52, 0x1d, 0x14, 0x4c, 0x88,
	    0xdb, 0xb8, 0xc7, 0x33, 0xf0, 0xe8, 0xb3, 0xf6 };
	memset(key3, 0xaa, sizeof(key3));
	memset(data3, 0xdd, sizeof(data3));

	hmac_test(key1, sizeof(key1), data1, strlen(data1), dig1, sizeof(dig1));
	hmac_test(key2, strlen(key2), data2, strlen(data2), dig2, sizeof(dig2));
	hmac_test(key3, sizeof(key3), data3, sizeof(data3), dig3, sizeof(dig3));

	return 0;
}

#endif
