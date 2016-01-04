/* libp11 example code: auth.c
 *
 * This examply simply connects to your smart card
 * and does a public key authentication.
 *
 * Feel free to copy all of the code as needed.
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <libp11.h>
#include <unistd.h>

#define RANDOM_SOURCE "/dev/urandom"
#define RANDOM_SIZE 20
#define MAX_SIGSIZE 256

static void do_fork();
static void error_queue(const char *name);

int main(int argc, char *argv[])
{
	PKCS11_CTX *ctx;
	PKCS11_SLOT *slots, *slot;
	PKCS11_CERT *certs;
	
	PKCS11_KEY *authkey;
	PKCS11_CERT *authcert;
	EVP_PKEY *pubkey = NULL;

	unsigned char *random = NULL, *signature = NULL;

	char password[20];
	int rc = 0, fd;
	unsigned int nslots, ncerts, siglen;

	if (argc < 2) {
		fprintf(stderr,
			"usage: %s /usr/lib/opensc-pkcs11.so [PIN]\n",
			argv[0]);
		return 1;
	}

	do_fork();
	ctx = PKCS11_CTX_new();
	error_queue("PKCS11_CTX_new");

	/* load pkcs #11 module */
	do_fork();
	rc = PKCS11_CTX_load(ctx, argv[1]);
	error_queue("PKCS11_CTX_load");
	if (rc) {
		fprintf(stderr, "loading pkcs11 engine failed: %s\n",
			ERR_reason_error_string(ERR_get_error()));
		rc = 1;
		goto nolib;
	}

	/* get information on all slots */
	do_fork();
	rc = PKCS11_enumerate_slots(ctx, &slots, &nslots);
	error_queue("PKCS11_enumerate_slots");
	if (rc < 0) {
		fprintf(stderr, "no slots available\n");
		rc = 2;
		goto noslots;
	}

	/* get first slot with a token */
	do_fork();
	slot = PKCS11_find_token(ctx, slots, nslots);
	error_queue("PKCS11_find_token");
	if (slot == NULL || slot->token == NULL) {
		fprintf(stderr, "no token available\n");
		rc = 3;
		goto notoken;
	}
	printf("Slot manufacturer......: %s\n", slot->manufacturer);
	printf("Slot description.......: %s\n", slot->description);
	printf("Slot token label.......: %s\n", slot->token->label);
	printf("Slot token manufacturer: %s\n", slot->token->manufacturer);
	printf("Slot token model.......: %s\n", slot->token->model);
	printf("Slot token serialnr....: %s\n", slot->token->serialnr);

	if (!slot->token->loginRequired)
		goto loggedin;

	/* get password */
	if (argc > 2) {
		strcpy(password, argv[2]);
	} else {
		exit(1);
	}

loggedin:
	/* perform pkcs #11 login */
	do_fork();
	rc = PKCS11_login(slot, 0, password);
	error_queue("PKCS11_login");
	memset(password, 0, strlen(password));
	if (rc != 0) {
		fprintf(stderr, "PKCS11_login failed\n");
		goto failed;
	}

	/* get all certs */
	do_fork();
	rc = PKCS11_enumerate_certs(slot->token, &certs, &ncerts);
	error_queue("PKCS11_enumerate_certs");
	if (rc) {
		fprintf(stderr, "PKCS11_enumerate_certs failed\n");
		goto failed;
	}
	if (ncerts <= 0) {
		fprintf(stderr, "no certificates found\n");
		goto failed;
	}

	/* use the first cert */
	authcert=&certs[0];

	/* get random bytes */
	random = OPENSSL_malloc(RANDOM_SIZE);
	if (random == NULL)
		goto failed;

	fd = open(RANDOM_SOURCE, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "fatal: cannot open RANDOM_SOURCE: %s\n",
				strerror(errno));
		goto failed;
	}

	rc = read(fd, random, RANDOM_SIZE);
	if (rc < 0) {
		fprintf(stderr, "fatal: read from random source failed: %s\n",
			strerror(errno));
		close(fd);
		goto failed;
	}

	if (rc < RANDOM_SIZE) {
		fprintf(stderr, "fatal: read returned less than %d<%d bytes\n",
			rc, RANDOM_SIZE);
		close(fd);
		goto failed;
	}

	close(fd);

	do_fork();
	authkey = PKCS11_find_key(authcert);
	error_queue("PKCS11_find_key");
	if (authkey == NULL) {
		fprintf(stderr, "no key matching certificate available\n");
		goto failed;
	}

	/* ask for a sha1 hash of the random data, signed by the key */
	siglen = MAX_SIGSIZE;
	signature = OPENSSL_malloc(MAX_SIGSIZE);
	if (signature == NULL)
		goto failed;

	/* do the operations in child */
	do_fork();
	rc = PKCS11_sign(NID_sha1, random, RANDOM_SIZE, signature, &siglen,
			authkey);
	error_queue("PKCS11_sign");
	if (rc != 1) {
		fprintf(stderr, "fatal: pkcs11_sign failed\n");
		goto failed;
	}

	/* verify the signature */
	pubkey = X509_get_pubkey(authcert->x509);
	if (pubkey == NULL) {
		fprintf(stderr, "could not extract public key\n");
		goto failed;
	}

	/* now verify the result */
	rc = RSA_verify(NID_sha1, random, RANDOM_SIZE,
			signature, siglen, pubkey->pkey.rsa);
	if (rc != 1) {
		fprintf(stderr, "fatal: RSA_verify failed\n");
		goto failed;
	}

	if (pubkey != NULL)
		EVP_PKEY_free(pubkey);

	if (random != NULL)
		OPENSSL_free(random);
	if (signature != NULL)
		OPENSSL_free(signature);

	PKCS11_release_all_slots(ctx, slots, nslots);
	PKCS11_CTX_unload(ctx);
	PKCS11_CTX_free(ctx);

	CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();

	printf("authentication successfull.\n");
	return 0;

failed:

notoken:
	PKCS11_release_all_slots(ctx, slots, nslots);

noslots:
	PKCS11_CTX_unload(ctx);

nolib:
	PKCS11_CTX_free(ctx);

	printf("authentication failed.\n");
	return 1;
}

static void do_fork()
{
	int status = 0;
	pid_t pid = fork();
	switch (pid) {
	case -1: /* failed */
		perror("fork");
		exit(5);
	case 0: /* child */
		return;
	default: /* parent */
		waitpid(pid, &status, 0);
		if (WIFEXITED(status))
			exit(WEXITSTATUS(status));
		if (WIFSIGNALED(status))
			fprintf(stderr, "Child terminated by signal #%d\n",
				WTERMSIG(status));
		else
			perror("waitpid");
		exit(2);
	}
}

static void error_queue(const char *name)
{
	if (ERR_peek_last_error()) {
		fprintf(stderr, "%s generated errors:\n", name);
		ERR_print_errors_fp(stderr);
	}
}