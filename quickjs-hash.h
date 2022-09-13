#ifndef QUICKJS_NET_H
#define QUICKJS_NET_H

#include "quickjs.h"

#ifdef __cplusplus
extern "C" {
#endif

JSModuleDef *js_init_module(JSContext *ctx, const char *module_name);

char *toBase64(const char *strIn, size_t lenIn);
size_t fromBase64(const char *strIn, size_t lenIn, uint8_t **out);

#ifdef __cplusplus
} /* extern "C" { */
#endif

#endif /* QUICKJS_NET_H */

