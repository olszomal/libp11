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
 */

#include <libp11.h>
#include <string.h>

#ifndef OPENSSL_NO_EC

#define CHECK_ERR(cond, txt, code) \
	do { \
		if (cond) { \
			fprintf(stderr, "%s\n", (txt)); \
			rc = (code); \
			goto end; \
		} \
	} while (0)

static void error_queue(const char *name)
{
	if (ERR_peek_last_error()) {
		fprintf(stderr, "%s generated errors:\n", name);
		ERR_print_errors_fp(stderr);
	}
}

static int pkey_equal(EVP_PKEY *a, EVP_PKEY *b)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	return EVP_PKEY_eq(a, b) == 1;
#else
	return EVP_PKEY_cmp(a, b) == 1;
#endif
}

int main(int argc, char *argv[])
{
	static unsigned char key_id[] = { 0x22, 0x33 };
	static char decoy_label[] = "duplicate-id-1";
	static char target_label[] = "duplicate-id-2";

	PKCS11_CTX *ctx = NULL;
	PKCS11_SLOT *slots = NULL, *slot;
	PKCS11_KEY *generated_key = NULL;
	PKCS11_KEY *public_keys = NULL;
	PKCS11_KEY public_template = {0};
	EVP_PKEY *actual_public = NULL;
	EVP_PKEY *expected_public = NULL;
	unsigned int nslots = 0, npublic = 0;
	int rc = 1;

	if (argc < 4) {
		fprintf(stderr, "usage: %s [MODULE] [TOKEN] [PIN]\n", argv[0]);
		return 1;
	}

	ctx = PKCS11_CTX_new();
	error_queue("PKCS11_CTX_new");
	CHECK_ERR(ctx == NULL, "PKCS11_CTX_new failed", 2);

	/* Load PKCS#11 module. */
	rc = PKCS11_CTX_load(ctx, argv[1]);
	error_queue("PKCS11_CTX_load");
	CHECK_ERR(rc < 0, "loading PKCS#11 module failed", 3);

	/* Get information on all slots. */
	rc = PKCS11_enumerate_slots(ctx, &slots, &nslots);
	error_queue("PKCS11_enumerate_slots");
	CHECK_ERR(rc < 0, "no slots available", 4);

	slot = PKCS11_find_token(ctx, slots, nslots);
	error_queue("PKCS11_find_token");

	while (slot != NULL) {
		if (slot->token != NULL &&
				slot->token->initialized &&
				slot->token->label != NULL &&
				strcmp(argv[2], slot->token->label) == 0)
			break;

		slot = PKCS11_find_next_token(ctx, slots, nslots, slot);
	}

	CHECK_ERR(slot == NULL || slot->token == NULL,
		"no token available", 5);

	printf("Found token:\n");
	printf("Slot manufacturer.: %s\n", slot->manufacturer);
	printf("Slot description.: %s\n", slot->description);
	printf("Slot token label.: %s\n", slot->token->label);
	printf("Slot token serialnr.: %s\n", slot->token->serialnr);

	rc = PKCS11_login(slot, 0, argv[3]);
	error_queue("PKCS11_login");
	CHECK_ERR(rc < 0, "PKCS11_login failed", 6);

	/*
	 * Generate a first key pair with the shared CKA_ID.
	 * This key acts as a decoy for an ambiguous CKA_ID lookup.
	 */
	rc = PKCS11_generate_key(slot->token, EVP_PKEY_EC,
		NID_X9_62_prime256v1, decoy_label,
		key_id, sizeof(key_id));
	error_queue("PKCS11_generate_key");
	CHECK_ERR(rc < 0, "Failed to generate first key pair", 7);

	/*
	 * Generate another key pair with the same CKA_ID and retain the
	 * returned private-key object.
	 */
	rc = PKCS11_generate_key_ext(slot->token, EVP_PKEY_EC,
		NID_X9_62_prime256v1, target_label,
		key_id, sizeof(key_id), &generated_key);
	error_queue("PKCS11_generate_key_ext");
	CHECK_ERR(rc < 0 || generated_key == NULL,
		"Failed to generate second key pair", 8);

	/*
	 * PKCS11_get_public_key() must resolve the public object paired with
	 * generated_key rather than an arbitrary public object with the same
	 * CKA_ID.
	 */
	actual_public = PKCS11_get_public_key(generated_key);
	error_queue("PKCS11_get_public_key");
	CHECK_ERR(actual_public == NULL,
		"Failed to get generated public key", 9);

	/*
	 * Resolve the expected public key unambiguously by its unique label.
	 */
	public_template.label = target_label;

	rc = PKCS11_enumerate_public_keys_ext(slot->token,
		&public_template, &public_keys, &npublic);
	error_queue("PKCS11_enumerate_public_keys_ext");
	CHECK_ERR(rc < 0, "Failed to enumerate public keys", 10);
	CHECK_ERR(npublic != 1,
		"Expected exactly one public key with the target label", 11);

	expected_public = PKCS11_get_public_key(&public_keys[0]);
	error_queue("PKCS11_get_public_key");
	CHECK_ERR(expected_public == NULL,
		"Failed to get expected public key", 12);

	CHECK_ERR(!pkey_equal(actual_public, expected_public),
		"PKCS11_get_public_key returned a public key from a different key pair",
		13);

	printf("Generated public key association is correct\n");
	rc = 0;

end:
	EVP_PKEY_free(expected_public);
	EVP_PKEY_free(actual_public);

	if (slots != NULL)
		PKCS11_release_all_slots(ctx, slots, nslots);

	if (ctx != NULL) {
		PKCS11_CTX_unload(ctx);
		PKCS11_CTX_free(ctx);
	}

	if (rc)
		printf("Failed (error code %d).\n", rc);
	else
		printf("Success.\n");

	return rc;
}

#else /* OPENSSL_NO_EC */

#include <stdio.h>

int main(void)
{
	fprintf(stderr, "Skipped: EC support not available\n");
	return 77;
}

#endif /* OPENSSL_NO_EC */

/* vim: set noexpandtab: */
