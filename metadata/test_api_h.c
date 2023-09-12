#include <stdio.h>

#ifndef PARAMS
#define PARAMS sphincs-sha2-128s
#define THASH simple
#endif

#define str(s) #s
#define xstr(s) str(s)

#ifndef NS
#define NS SPX
#endif

#define PASTER(x, y) x##_CRYPTO##y
#define EVALUATOR(x, y) PASTER(x, y)
#define NAMESPACE(fun) EVALUATOR(NS, fun)

#include xstr(api/PARAMS-THASH.h)

#define SPX_CRYPTO_ALGNAME        NAMESPACE(_ALGNAME)
#define SPX_CRYPTO_BYTES          NAMESPACE(_BYTES)
#define SPX_CRYPTO_PUBLICKEYBYTES NAMESPACE(_PUBLICKEYBYTES)
#define SPX_CRYPTO_SECRETKEYBYTES NAMESPACE(_SECRETKEYBYTES)

#include xstr(../ref/api.h)

int main(void) {
    int res = 0;

    printf("Comparing %s with %s headers\n", CRYPTO_ALGNAME, SPX_CRYPTO_ALGNAME);

    if (CRYPTO_BYTES != SPX_CRYPTO_BYTES) {
        puts("Mismatch for CRYPTO_BYTES");
        res = 1;
    }

    if (CRYPTO_PUBLICKEYBYTES != SPX_CRYPTO_PUBLICKEYBYTES) {
        puts("Mismatch for CRYPTO_PUBLICKEYBYTES");
        res = 1;
    }

    if (CRYPTO_SECRETKEYBYTES != SPX_CRYPTO_SECRETKEYBYTES) {
        puts("Mismatch for CRYPTO_SECRETKEYBYTES");
        res = 1;
    }

    return res;
}
