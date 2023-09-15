#include "osslv3.h"

#if WITH_OPENSSL_V3

#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include "ssherr.h"
#include "openbsd-compat/openbsd-compat.h"

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

static int
get_octet_string_param(EVP_PKEY *pkey, const char *name, unsigned char **vp, size_t *lenp)
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
ssh_get_rsa_key_params(EVP_PKEY *pkey, struct ssh_rsa_key_params *kp, int private)
{
	int r = SSH_ERR_LIBCRYPTO_ERROR;

	if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &kp->n) != 1 ||
	    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &kp->e) != 1)
		goto out;

	if (private) {
		if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_D, &kp->d) != 1 ||
		    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, &kp->p) != 1 ||
		    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, &kp->q) != 1 ||
		    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &kp->iqmp) != 1)
			goto out;
	}

	r = 0;

 out:
	return r;
}

static int
ssh_rsa_new_pkey2(const struct ssh_rsa_key_params *kp, const struct ssh_rsa_exponents *rsa_exp, EVP_PKEY **pkeyp)
{
	EVP_PKEY_CTX *ctx = NULL;
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;
	int r = SSH_ERR_LIBCRYPTO_ERROR;
	EVP_PKEY *old_pkey = *pkeyp;

	if ((ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL)) == NULL)
		goto out;

	if (EVP_PKEY_fromdata_init(ctx) != 1)
		goto out;

	if ((bld = OSSL_PARAM_BLD_new()) == NULL)
		goto out;

	if (push_opt_bn(bld, OSSL_PKEY_PARAM_RSA_N, kp->n) < 0 ||
	    push_opt_bn(bld, OSSL_PKEY_PARAM_RSA_E, kp->e) < 0 ||
	    push_opt_bn(bld, OSSL_PKEY_PARAM_RSA_D, kp->d) < 0 ||
	    push_opt_bn(bld, OSSL_PKEY_PARAM_RSA_FACTOR1, kp->p) < 0 ||
	    push_opt_bn(bld, OSSL_PKEY_PARAM_RSA_FACTOR2, kp->q) < 0 ||
	    push_opt_bn(bld, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, kp->iqmp) < 0 ||
	    push_opt_bn(bld, OSSL_PKEY_PARAM_RSA_EXPONENT1, rsa_exp->dmp1) < 0 ||
	    push_opt_bn(bld, OSSL_PKEY_PARAM_RSA_EXPONENT2, rsa_exp->dmq1) < 0)
		goto out;

	if ((params = OSSL_PARAM_BLD_to_param(bld)) == NULL)
		goto out;

	if (EVP_PKEY_fromdata(ctx, pkeyp, EVP_PKEY_KEYPAIR, params) != 1)
		goto out;

	r = 0;
 out:
	if (old_pkey != *pkeyp)
		EVP_PKEY_free(old_pkey);
	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(bld);
	EVP_PKEY_CTX_free(ctx);
	return r;
}

int
ssh_rsa_new_pkey(const struct ssh_rsa_key_params *kp, EVP_PKEY **pkeyp)
{
	BIGNUM *aux = NULL, *d_consttime = NULL;
	struct ssh_rsa_exponents rsa_exp;
	BN_CTX *ctx = NULL;
	int r;

	memset(&rsa_exp, 0, sizeof rsa_exp);
	if ((ctx = BN_CTX_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;

	if (kp->d != NULL &&
	    kp->p != NULL &&
	    kp->q != NULL) {
		if ((aux = BN_new()) == NULL ||
		    (rsa_exp.dmq1 = BN_new()) == NULL ||
		    (rsa_exp.dmp1 = BN_new()) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}

		if ((d_consttime = BN_dup(kp->d)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}

		BN_set_flags(aux, BN_FLG_CONSTTIME);
		BN_set_flags(d_consttime, BN_FLG_CONSTTIME);

		if ((BN_sub(aux, kp->q, BN_value_one()) == 0) ||
		    (BN_mod(rsa_exp.dmq1, d_consttime, aux, ctx) == 0) ||
		    (BN_sub(aux, kp->p, BN_value_one()) == 0) ||
		    (BN_mod(rsa_exp.dmp1, d_consttime, aux, ctx) == 0)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
	}

	r = ssh_rsa_new_pkey2(kp, &rsa_exp, pkeyp);

 out:
	BN_clear_free(aux);
	BN_clear_free(d_consttime);
	BN_clear_free(rsa_exp.dmp1);
	BN_clear_free(rsa_exp.dmq1);
	BN_CTX_free(ctx);
	return r;
}

void
ssh_rsa_key_params_deinit(struct ssh_rsa_key_params *kp)
{
	BN_clear_free(kp->n);
	BN_clear_free(kp->e);
	BN_clear_free(kp->d);
	BN_clear_free(kp->p);
	BN_clear_free(kp->q);
	BN_clear_free(kp->iqmp);
	explicit_bzero(kp, sizeof *kp);
}

int
ssh_get_dsa_key_params(EVP_PKEY *pkey, struct ssh_dsa_key_params *dsa_param, int private)
{
	int r = SSH_ERR_LIBCRYPTO_ERROR;
	BIGNUM *p = NULL;
	BIGNUM *q = NULL;
	BIGNUM *g = NULL;
	BIGNUM *pub_key = NULL;
	BIGNUM *priv_key = NULL;

	if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_P, &p) != 1 ||
	    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_Q, &q) != 1 ||
	    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_G, &g) != 1 ||
	    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, &pub_key) != 1) {
		goto out;
	}

	if (private) {
		if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv_key) != 1)
			goto out;
	}

	dsa_param->p = p;
	p = NULL;
	dsa_param->q = q;
	q = NULL;
	dsa_param->g = g;
	g = NULL;
	dsa_param->pub_key = pub_key;
	pub_key = NULL;
	dsa_param->priv_key = priv_key;
	priv_key = NULL;
	r = 0;
 out:
	BN_free(p);
	BN_free(q);
	BN_free(g);
	BN_free(pub_key);
	BN_clear_free(priv_key);
	return r;
}

int
ssh_dsa_new_pkey(const struct ssh_dsa_key_params *kp, EVP_PKEY **pkeyp)
{
	int r = SSH_ERR_LIBCRYPTO_ERROR;
	EVP_PKEY_CTX *kctx = NULL;
	OSSL_PARAM_BLD *param_bld = NULL;
	OSSL_PARAM *param = NULL;
	EVP_PKEY *old_pkey = *pkeyp;

	if ((kctx = EVP_PKEY_CTX_new_from_name(NULL, "DSA", NULL)) == NULL)
		goto out;

	if (EVP_PKEY_fromdata_init(kctx) != 1)
		goto out;

	if ((param_bld = OSSL_PARAM_BLD_new()) == NULL)
		goto out;

	if (push_opt_bn(param_bld, OSSL_PKEY_PARAM_PUB_KEY, kp->pub_key) < 0 ||
	    push_opt_bn(param_bld, OSSL_PKEY_PARAM_PRIV_KEY, kp->priv_key) < 0 ||
	    push_opt_bn(param_bld, OSSL_PKEY_PARAM_FFC_P, kp->p) < 0 ||
	    push_opt_bn(param_bld, OSSL_PKEY_PARAM_FFC_G, kp->g) < 0 ||
	    push_opt_bn(param_bld, OSSL_PKEY_PARAM_FFC_Q, kp->q) < 0)
		goto out;

	if ((param = OSSL_PARAM_BLD_to_param(param_bld)) == NULL)
		goto out;

	if (EVP_PKEY_fromdata(kctx, pkeyp, EVP_PKEY_KEYPAIR, param) != 1)
		goto out;

#ifdef DEBUG_PK
	EVP_PKEY_print_private_fp(stderr, *pkeyp, 8, NULL);
#endif

	r = 0;

 out:
	if (old_pkey != *pkeyp)
		EVP_PKEY_free(old_pkey);
	OSSL_PARAM_free(param);
	OSSL_PARAM_BLD_free(param_bld);
	EVP_PKEY_CTX_free(kctx);
	return r;
}

void
ssh_dsa_key_params_deinit(struct ssh_dsa_key_params *kp)
{
	BN_clear_free(kp->p);
	BN_clear_free(kp->g);
	BN_clear_free(kp->q);
	BN_clear_free(kp->pub_key);
	BN_clear_free(kp->priv_key);
	explicit_bzero(kp, sizeof *kp);
}

int
ssh_get_ec_key_params(EVP_PKEY *pkey, struct ssh_ec_key_params *kp, int private)
{
	int r = SSH_ERR_LIBCRYPTO_ERROR;
	int nid;
	unsigned char *pub = NULL;
	size_t pub_len = 0;
	BIGNUM *priv = NULL;
	char gname[100];
	size_t gname_len;

	if (EVP_PKEY_get_group_name(pkey, gname, sizeof gname, &gname_len) != 1)
		goto out;

	if ((nid = OBJ_txt2nid(gname)) < 0)
		goto out;

	if ((r = get_octet_string_param(pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, &pub, &pub_len)) != 0)
		goto out;

	if (pub[0] != POINT_CONVERSION_UNCOMPRESSED)
		goto out;

	if (private) {
		if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv) != 1)
			goto out;
	}

	kp->curve_nid = nid;
	kp->pub = pub;
	pub = NULL;
	kp->pub_len = pub_len;
	kp->exponent = priv;
	priv = NULL;

	r = 0;

 out:
	BN_clear_free(priv);
	freezero(pub, pub_len);
	return r;
}

int
ssh_ec_new_pkey(const struct ssh_ec_key_params *kp, EVP_PKEY **pkeyp)
{
	int r = SSH_ERR_LIBCRYPTO_ERROR;
	EVP_PKEY_CTX *kctx = NULL;
	OSSL_PARAM_BLD *param_bld = NULL;
	OSSL_PARAM *param = NULL;
	const char *group_name = NULL;
	EVP_PKEY *old_pkey = *pkeyp;

	if ((kctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL)) == NULL)
		goto out;

	if (EVP_PKEY_fromdata_init(kctx) != 1)
		goto out;

	if ((param_bld = OSSL_PARAM_BLD_new()) == NULL)
		goto out;

	if ((group_name = OBJ_nid2sn(kp->curve_nid)) == NULL) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}

	if (push_opt_utf8(param_bld, OSSL_PKEY_PARAM_GROUP_NAME, group_name, 0) < 0 ||
	    push_opt_oct(param_bld, OSSL_PKEY_PARAM_PUB_KEY, kp->pub, kp->pub_len) < 0 ||
	    push_opt_bn(param_bld, OSSL_PKEY_PARAM_PRIV_KEY, kp->exponent) < 0) {
		goto out;
	}

	if ((param = OSSL_PARAM_BLD_to_param(param_bld)) == NULL)
		goto out;

	if (EVP_PKEY_fromdata(kctx, pkeyp, EVP_PKEY_KEYPAIR, param) != 1)
		goto out;

#ifdef DEBUG_PK
	EVP_PKEY_print_private_fp(stderr, *pkeyp, 8, NULL);
#endif

	r = 0;

 out:
	if (old_pkey != *pkeyp)
		EVP_PKEY_free(old_pkey);
	OSSL_PARAM_free(param);
	OSSL_PARAM_BLD_free(param_bld);
	EVP_PKEY_CTX_free(kctx);
	return r;
}

void
ssh_ec_key_params_deinit(struct ssh_ec_key_params *kp)
{
	freezero(kp->pub, kp->pub_len);
	BN_clear_free(kp->exponent);
	explicit_bzero(kp, sizeof *kp);
}

int
ssh_get_ed25519_key_params(EVP_PKEY *pkey, struct ssh_ed25519_key_params *kp, int private)
{
	int ret;
	size_t pklen, sklen;

	if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &pklen) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	if (pklen != ED25519_PK_SZ) {
		ret = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, &kp->sk[ED25519_SK_SZ - ED25519_PK_SZ], ED25519_PK_SZ, &pklen) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	if (private) {
		if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0, &sklen) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}

		if (sklen != ED25519_SK_SZ - ED25519_PK_SZ) {
			ret = SSH_ERR_INTERNAL_ERROR;
			goto out;
		}

		if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, kp->sk, ED25519_SK_SZ, &sklen) != 1) {
			ret = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
	}

	ret = 0;
 out:
	return ret;
}

int
ssh_ed25519_new_pkey(const struct ssh_ed25519_key_params *kp, int priv, EVP_PKEY **pkeyp)
{
	EVP_PKEY_CTX *ctx = NULL;
	OSSL_PARAM_BLD *param_bld = NULL;
	OSSL_PARAM *param = NULL;
	int r = SSH_ERR_LIBCRYPTO_ERROR;

	if ((ctx = EVP_PKEY_CTX_new_from_name(NULL, SN_ED25519, NULL)) == NULL)
		goto out;

	if (EVP_PKEY_fromdata_init(ctx) != 1)
		goto out;

	if ((param_bld = OSSL_PARAM_BLD_new()) == NULL)
		goto out;

	if (OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_PUB_KEY, &kp->sk[ED25519_SK_SZ - ED25519_PK_SZ], ED25519_PK_SZ) != 1)
		goto out;

	if (priv) {
		if (OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_PRIV_KEY, kp->sk, ED25519_SK_SZ - ED25519_PK_SZ) != 1)
			goto out;
	}

	if ((param = OSSL_PARAM_BLD_to_param(param_bld)) == NULL)
		goto out;

	if (EVP_PKEY_fromdata(ctx, pkeyp, EVP_PKEY_KEYPAIR, param) != 1) {
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

void
ssh_ed25519_key_params_deinit(struct ssh_ed25519_key_params *p)
{
	explicit_bzero(p, sizeof *p);
}

#endif /* WITH_OPENSSL_V3 */
