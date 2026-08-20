/*
 * Copyright (C) 2026 OpenSC Project
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
 */

#define OPENSSL_SUPPRESS_DEPRECATED

#include <stdio.h>
#include <stdlib.h>

#include <openssl/opensslconf.h>
#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L && \
	OPENSSL_VERSION_NUMBER < 0x40000000L && \
	!defined(OPENSSL_NO_DEPRECATED_3_0) && \
	!defined(OPENSSL_NO_ENGINE) && \
	!defined(OPENSSL_NO_ECX)

#include <libp11.h>

#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

static EVP_PKEY *generate_software_key(void)
{
	EVP_PKEY_CTX *ctx;
	EVP_PKEY *key = NULL;

	ctx = EVP_PKEY_CTX_new_from_name(NULL, "ED25519", NULL);
	if (!ctx)
		return NULL;

	if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_generate(ctx, &key) <= 0) {
		EVP_PKEY_free(key);
		key = NULL;
	}
	EVP_PKEY_CTX_free(ctx);
	return key;
}

static int sign_message(EVP_PKEY *key)
{
	static const unsigned char message[] = "libp11 software Ed25519 test";
	EVP_MD_CTX *ctx = NULL;
	unsigned char *sig = NULL;
	size_t siglen = 0;
	int ret = 0;

	ctx = EVP_MD_CTX_new();
	if (!ctx)
		goto cleanup;

	if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, key) <= 0 ||
			EVP_DigestSign(ctx, NULL, &siglen,
				message, sizeof(message) - 1) <= 0)
		goto cleanup;

	sig = OPENSSL_malloc(siglen);
	if (!sig)
		goto cleanup;

	if (EVP_DigestSign(ctx, sig, &siglen, message, sizeof(message) - 1) <= 0)
		goto cleanup;

	EVP_MD_CTX_free(ctx);
	ctx = EVP_MD_CTX_new();
	if (!ctx)
		goto cleanup;

	if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) <= 0 ||
			EVP_DigestVerify(ctx, sig, siglen,
				message, sizeof(message) - 1) <= 0)
		goto cleanup;

	ret = 1;

cleanup:
	OPENSSL_free(sig);
	EVP_MD_CTX_free(ctx);
	return ret;
}

/*
 * Attach the test ENGINE only to an EVP_PKEY returned by this libp11
 * context. This avoids process-wide EVP_PKEY_METHOD registration.
 */
static int set_pkey_engine(PKCS11_KEY *key, EVP_PKEY *pkey, void *user_data)
{
	ENGINE *engine = user_data;

	(void)key;

	if (!pkey || !engine)
		return -1;

	return EVP_PKEY_set1_engine(pkey, engine) ? 0 : -1;
}

int main(int argc, char **argv)
{
	ENGINE *engine = NULL;
	PKCS11_CTX *ctx = NULL;
	PKCS11_SLOT *slots = NULL, *slot;
	PKCS11_KEY *keys;
	EVP_PKEY *software_key = NULL;
	EVP_PKEY *new_software_key = NULL;
	EVP_PKEY *token_key = NULL;
	unsigned int nslots = 0, nkeys = 0;
	int ret = EXIT_FAILURE;

	if (argc != 3) {
		fprintf(stderr, "usage: %s [module] [PIN]\n", argv[0]);
		return EXIT_FAILURE;
	}

	/*
	 * First make sure a normal provider-backed Ed25519 key works before
	 * any PKCS#11 key is loaded.
	 */
	software_key = generate_software_key();
	if (!software_key ||
			!EVP_PKEY_get0_provider(software_key) ||
			!sign_message(software_key)) {
		fprintf(stderr, "Initial software Ed25519 operation failed\n");
		goto cleanup;
	}

	ctx = PKCS11_CTX_new();
	if (!ctx) {
		fprintf(stderr, "Failed to initialize PKCS#11\n");
		goto cleanup;
	}

	/*
	 * Create a small test ENGINE exposing libp11's PKEY methods.
	 * It is not registered globally. The callback attaches it only to
	 * private keys returned by this PKCS11_CTX.
	 */
	engine = ENGINE_new();
	if (!engine || !ENGINE_set_id(engine, "libp11-test-pkey") ||
			!ENGINE_set_name(engine, "libp11 test PKEY methods") ||
			!ENGINE_set_pkey_meths(engine, PKCS11_pkey_meths)) {
		fprintf(stderr, "Failed to initialize test PKEY ENGINE\n");
		goto cleanup;
	}

	if (PKCS11_CTX_set_pkey_callback(ctx,
			PKCS11_PKEY_CALLBACK_GET_PRIVATE_KEY,
			set_pkey_engine, engine) < 0) {
		fprintf(stderr, "Failed to initialize PKEY callback\n");
		goto cleanup;
	}

	if (PKCS11_CTX_load(ctx, argv[1]) < 0 ||
			PKCS11_enumerate_slots(ctx, &slots, &nslots) < 0) {
		fprintf(stderr, "Failed to initialize PKCS#11\n");
		goto cleanup;
	}

	slot = PKCS11_find_token(ctx, slots, nslots);
	if (!slot || PKCS11_login(slot, 0, argv[2]) < 0 ||
			PKCS11_enumerate_keys(slot->token, &keys, &nkeys) < 0 ||
			nkeys == 0) {
		fprintf(stderr, "Failed to find a PKCS#11 private key\n");
		goto cleanup;
	}

	/*
	 * PKCS11_get_private_key() invokes the callback registered above,
	 * so only this EVP_PKEY receives the test ENGINE.
	 */
	token_key = PKCS11_get_private_key(&keys[0]);
	if (!token_key) {
		fprintf(stderr, "PKCS11_get_private_key failed\n");
		goto cleanup;
	}

	/*
	 * The ENGINE-scoped Ed25519 PKEY method should route signing through
	 * libp11 and ultimately CKM_EDDSA.
	 */
	if (!sign_message(token_key)) {
		fprintf(stderr, "Ed25519 signing with the PKCS#11 key failed\n");
		goto cleanup;
	}

	/*
	 * Loading and using a PKCS#11 key must not alter a provider-backed
	 * Ed25519 key created earlier, nor affect subsequently created keys.
	 */
	new_software_key = generate_software_key();

	if (!EVP_PKEY_get0_provider(software_key) ||
			!sign_message(software_key) ||
			!new_software_key ||
			!EVP_PKEY_get0_provider(new_software_key) ||
			!sign_message(new_software_key)) {
		fprintf(stderr, "PKCS#11 key affected an unrelated software Ed25519 key\n");
		goto cleanup;
	}

	ret = EXIT_SUCCESS;

cleanup:
	if (ret != EXIT_SUCCESS)
		ERR_print_errors_fp(stderr);

	EVP_PKEY_free(new_software_key);
	EVP_PKEY_free(token_key);
	EVP_PKEY_free(software_key);

	/*
	 * The callback keeps a borrowed pointer to engine, so unregister it
	 * before freeing the ENGINE.
	 */
	if (ctx)
		PKCS11_CTX_set_pkey_callback(ctx,
			PKCS11_PKEY_CALLBACK_GET_PRIVATE_KEY,
			NULL, NULL);

	ENGINE_free(engine);

	if (slots)
		PKCS11_release_all_slots(ctx, slots, nslots);

	if (ctx) {
		PKCS11_CTX_unload(ctx);
		PKCS11_CTX_free(ctx);
	}

	return ret;
}

#else

int main(void)
{
	fprintf(stderr,
		"Skipped: test requires Ed25519 and ENGINE with OpenSSL 3.x\n");
	return 77;
}

#endif

/* vim: set noexpandtab: */
