#include "yespower.h"
#include "sysendian.h"

static const yespower_params_t v2 = {YESPOWER_1_0, 4096, 10000, NULL, 0};

void hash_extra_yespower(const void *data, size_t length, char *hash){
yespower_tls(data, 80, &v2, (uint8_t *)hash);
}
