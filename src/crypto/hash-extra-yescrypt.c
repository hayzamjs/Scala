#include "yescrypt.h"
#include "sha256_c.h"
#include "yescrypt-best_c.h"

/* Need Tweaking */
#define YESCRYPT_N 2048
#define YESCRYPT_R 16
#define YESCRYPT_P 1
#define YESCRYPT_T 0
#define YESCRYPT_FLAGS (YESCRYPT_RW | YESCRYPT_PWXFORM)

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#ifdef __clang__

static int yescrypt_cn(const uint8_t *passwd, size_t passwdlen,
                            const uint8_t *salt, size_t saltlen,
                            uint8_t *buf, size_t buflen)
{
    yescrypt_shared_t shared;
    yescrypt_local_t local;
    int retval;
    
    if (yescrypt_init_shared(&shared, NULL, 0,
                             0, 0, 0, YESCRYPT_SHARED_DEFAULTS, 0, NULL, 0))
        return -1;
    if (yescrypt_init_local(&local)) {
        yescrypt_free_shared(&shared);
        return -1;
    }
    retval = yescrypt_kdf(&shared, &local, passwd, passwdlen, salt, saltlen,
                          YESCRYPT_N, YESCRYPT_R, YESCRYPT_P, YESCRYPT_T,
                          YESCRYPT_FLAGS, buf, buflen);
    if (yescrypt_free_local(&local)) {
        yescrypt_free_shared(&shared);
        return -1;
    }
    if (yescrypt_free_shared(&shared))
        return -1;
    
    return retval;
}

#else

static int yescrypt_cn(const uint8_t *passwd, size_t passwdlen,
                            const uint8_t *salt, size_t saltlen,
                            uint8_t *buf, size_t buflen)
{
    static __thread int initialized = 0;
    static __thread yescrypt_shared_t shared;
    static __thread yescrypt_local_t local;
    int retval;
    if (!initialized) {
        /* "shared" could in fact be shared, but it's simpler to keep it private
         * along with "local".  It's dummy and tiny anyway. */
        if (yescrypt_init_shared(&shared, NULL, 0,
                                 0, 0, 0, YESCRYPT_SHARED_DEFAULTS, 0, NULL, 0))
            return -1;
        if (yescrypt_init_local(&local)) {
            yescrypt_free_shared(&shared);
            return -1;
        }
        initialized = 1;
    }
    retval = yescrypt_kdf(&shared, &local, passwd, passwdlen, salt, saltlen,
                          YESCRYPT_N, YESCRYPT_R, YESCRYPT_P, YESCRYPT_T,
                          YESCRYPT_FLAGS, buf, buflen);
#if 0
    if (yescrypt_free_local(&local)) {
        yescrypt_free_shared(&shared);
        return -1;
    }
    if (yescrypt_free_shared(&shared))
        return -1;
    initialized = 0;
#endif
    if (retval < 0) {
        yescrypt_free_local(&local);
        yescrypt_free_shared(&shared);
    }
    return retval;
}

#endif

void hash_extra_yescrypt(const void *data, size_t length, char *hash){

    yescrypt_cn((const uint8_t *) data, 80,
                     (const uint8_t *) data, 80,
                     (uint8_t *) hash, 32);

}
