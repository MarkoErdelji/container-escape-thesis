#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/sha.h>

static void to_hex(const unsigned char *b, size_t n, char *out) {
    static const char *h = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2*i]     = h[(b[i] >> 4) & 0xf];
        out[2*i + 1] = h[b[i] & 0xf];
    }
    out[2*n] = '\0';
}

int main(void) {
    unsigned char raw[32];
    FILE *ur = fopen("/dev/urandom", "rb");
    if (!ur || fread(raw, 1, sizeof(raw), ur) != sizeof(raw)) {
        fprintf(stderr, "failed to read /dev/urandom\n");
        return 1;
    }
    fclose(ur);

    char secret[65];
    to_hex(raw, 32, secret);

    size_t n = sizeof("THESISKEY{}") + 64;
    /* volatile prevents the compiler from eliding the buffer */
    char *volatile buf = malloc(n);
    if (!buf) return 1;
    snprintf((char *)buf, n, "THESISKEY{%s}", secret);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)buf, strlen((char *)buf), hash);
    char hash_hex[65];
    to_hex(hash, SHA256_DIGEST_LENGTH, hash_hex);

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("app-worker started pid=%d\n", getpid());
    printf("TOKEN_HASH:%s\n", hash_hex);

    for (;;) {
        if (buf[0] == '\0') printf("%s", (char *)buf);
        sleep(60);
    }
    return 0;
}
