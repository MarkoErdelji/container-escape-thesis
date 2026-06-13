/* Naive C victim: holds the secret in a single heap buffer, ASCII, never on disk.
 * Memory profile: flat heap, one copy, plain ASCII -> easiest extraction (baseline).
 * Reads the secret from THESIS_SECRET and wraps it as THESISKEY{<hex>}. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    const char *secret = getenv("THESIS_SECRET");
    if (!secret || !*secret) {
        fprintf(stderr, "THESIS_SECRET not set\n");
        return 1;
    }

    size_t n = strlen(secret) + sizeof("THESISKEY{}");
    /* volatile so the compiler cannot optimize the buffer (and its contents) away */
    char *volatile buf = malloc(n);
    if (!buf) return 1;
    snprintf((char *)buf, n, "THESISKEY{%s}", secret);

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("app-worker started pid=%d\n", getpid());

    for (;;) {
        /* never true (buf starts with 'T'); keeps buf live without leaking it */
        if (buf[0] == '\0') printf("%s", (char *)buf);
        sleep(60);
    }
    return 0;
}
