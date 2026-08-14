/*
 * Copyright © 2026 Mobi - Com Polska Sp. z o.o.
 * Author: Małgorzata Olszówka <Malgorzata.Olszowka@stunnel.org>
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Test RSA-PSS signing with an EVP_PKEY retrieved directly through
 * PKCS11_get_private_key().
 *
 * No ENGINE API is used.
 */

#include <stdio.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <libp11.h>

static const unsigned char message[] =
	"libp11 direct RSA-PSS signing test";

static void error_queue(const char *name)
{
	if (ERR_peek_error() == 0)
		return;

	fprintf(stderr, "%s generated errors:\n", name);
	ERR_print_errors_fp(stderr);
}

static int is_rsa_key(EVP_PKEY *pkey)
{
	int type;

	if (pkey == NULL)
		return 0;

	type = EVP_PKEY_base_id(pkey);
	if (type == EVP_PKEY_RSA)
		return 1;

#ifdef EVP_PKEY_RSA_PSS
	if (type == EVP_PKEY_RSA_PSS)
		return 1;
#endif

	return 0;
}


static int sign_pss(EVP_PKEY *pkey,
	const unsigned char *digest, size_t digest_len,
	unsigned char **signature, size_t *signature_len)
{
	EVP_PKEY_CTX *ctx = NULL;
	unsigned char *buffer = NULL;
	size_t buffer_len = 0;
	int ret = 0;

	ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (ctx == NULL)
		goto end;

	if (EVP_PKEY_sign_init(ctx) <= 0)
		goto end;

	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0)
		goto end;

	if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0)
		goto end;

	if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0)
		goto end;

	if (EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, RSA_PSS_SALTLEN_DIGEST) <= 0)
		goto end;

	if (EVP_PKEY_sign(ctx, NULL, &buffer_len,digest, digest_len) <= 0)
		goto end;

	buffer = OPENSSL_malloc(buffer_len);
	if (buffer == NULL)
		goto end;

	if (EVP_PKEY_sign(ctx, buffer, &buffer_len,digest, digest_len) <= 0)
		goto end;

	*signature = buffer;
	*signature_len = buffer_len;
	buffer = NULL;

	ret = 1;

end:
	if (!ret)
		error_queue("RSA-PSS signing");

	OPENSSL_free(buffer);
	EVP_PKEY_CTX_free(ctx);

	return ret;
}

static int verify_pss(EVP_PKEY *pkey,
	const unsigned char *digest, size_t digest_len,
	const unsigned char *signature, size_t signature_len)
{
	EVP_PKEY_CTX *ctx = NULL;
	int ret = 0;

	ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (ctx == NULL)
		goto end;

	if (EVP_PKEY_verify_init(ctx) <= 0)
		goto end;

	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0)
		goto end;

	if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0)
		goto end;

	if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0)
		goto end;

	if (EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, RSA_PSS_SALTLEN_DIGEST) <= 0)
		goto end;

	if (EVP_PKEY_verify(ctx, signature, signature_len, digest, digest_len) != 1)
		goto end;

	ret = 1;

end:
	if (!ret)
		error_queue("RSA-PSS verification");

	EVP_PKEY_CTX_free(ctx);

	return ret;
}

int main(int argc, char *argv[])
{
	PKCS11_CTX *ctx = NULL;
	PKCS11_SLOT *slots = NULL;
	PKCS11_SLOT *slot = NULL;
	PKCS11_KEY *keys = NULL;
	EVP_PKEY *pkey = NULL;
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned char *signature = NULL;
	unsigned int digest_len = 0;
	unsigned int nslots = 0;
	unsigned int nkeys = 0;
	size_t signature_len = 0;
	const char *pin;
	int logged_in = 0;
	int module_loaded = 0;
	int rc = 1;

	if (argc < 2) {
		fprintf(stderr, "usage: %s /path/to/pkcs11-module.so [PIN]\n",
			argv[0]);
		return 1;
	}

	pin = argc >= 3 ? argv[2] : NULL;

	ctx = PKCS11_CTX_new();
	if (ctx == NULL)
		goto end;

	if (PKCS11_CTX_load(ctx, argv[1]) < 0) {
		fprintf(stderr, "PKCS11_CTX_load failed\n");
		goto end;
	}

	module_loaded = 1;

	if (PKCS11_enumerate_slots(ctx, &slots, &nslots) < 0) {
		fprintf(stderr, "PKCS11_enumerate_slots failed\n");
		goto end;
	}

	slot = PKCS11_find_token(ctx, slots, nslots);
	if (slot == NULL || slot->token == NULL) {
		fprintf(stderr, "No token available\n");
		goto end;
	}

	if (slot->token->loginRequired && pin == NULL) {
		fprintf(stderr, "The token requires a PIN\n");
		goto end;
	}

	if (pin != NULL) {
		if (PKCS11_login(slot, 0, pin) != 0) {
			fprintf(stderr, "PKCS11_login failed\n");
			goto end;
		}
		logged_in = 1;
	}

	if (PKCS11_enumerate_keys(slot->token, &keys, &nkeys) < 0) {
		fprintf(stderr, "PKCS11_enumerate_keys failed\n");
		goto end;
	}

	if (nkeys == 0) {
		fprintf(stderr, "No private keys found\n");
		goto end;
	}

	pkey = PKCS11_get_private_key(&keys[0]);
	if (pkey == NULL) {
		fprintf(stderr, "PKCS11_get_private_key failed\n");
		error_queue("PKCS11_get_private_key");
		goto end;
	}

	if (!is_rsa_key(pkey)) {
		fprintf(stderr, "The private key is not RSA\n");
		goto end;
	}

	printf("RSA key size............: %d bits\n", EVP_PKEY_bits(pkey));

	if (EVP_Digest(message, sizeof(message) - 1,
			digest, &digest_len,
			EVP_sha256(), NULL) != 1) {
		fprintf(stderr, "EVP_Digest failed\n");
		goto end;
	}

	if (!sign_pss(pkey, digest, digest_len, &signature, &signature_len))
		goto end;

	printf("RSA-PSS signature.......: %lu bytes\n",
		(unsigned long)signature_len);

	/*
	 * The private EVP_PKEY also contains the RSA public components,
	 * so the same key can be used for verification.
	 */
	if (!verify_pss(pkey, digest, digest_len, signature, signature_len))
		goto end;

	printf("RSA-PSS verification....: successful\n");
	printf("Direct libp11 API test...: successful\n");

	rc = 0;

end:
	OPENSSL_free(signature);
	EVP_PKEY_free(pkey);

	if (logged_in)
		PKCS11_logout(slot);

	if (slots != NULL)
		PKCS11_release_all_slots(ctx, slots, nslots);

	if (module_loaded)
		PKCS11_CTX_unload(ctx);

	PKCS11_CTX_free(ctx);

	return rc;
}

/* vim: set noexpandtab: */
