#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "quickjs-hash.h"
#include "cutils.h"

#define HASH_CHUNKSIZE 512

enum DigestType {
	DIGEST_MD5,
	DIGEST_SHA256
};

static const char b64_table[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *base64_encode(const uint8_t *data, size_t len, size_t *outlen)
{
	size_t olen = 4 * ((len + 2) / 3);
	char *out = malloc(olen + 1);
	if (!out) return NULL;

	size_t i = 0, j = 0;
	while (i < len) {
		uint32_t a = i < len ? data[i++] : 0;
		uint32_t b = i < len ? data[i++] : 0;
		uint32_t c = i < len ? data[i++] : 0;
		uint32_t triple = (a << 16) | (b << 8) | c;

		out[j++] = b64_table[(triple >> 18) & 0x3F];
		out[j++] = b64_table[(triple >> 12) & 0x3F];
		out[j++] = (i > len + 1) ? '=' : b64_table[(triple >> 6) & 0x3F];
		out[j++] = (i > len) ? '=' : b64_table[triple & 0x3F];
	}
	out[j] = '\0';
	if (outlen) *outlen = j;
	return out;
}

/* simple lookup */
static inline int b64_inv(char c)
{
	if ('A' <= c && c <= 'Z') return c - 'A';
	if ('a' <= c && c <= 'z') return c - 'a' + 26;
	if ('0' <= c && c <= '9') return c - '0' + 52;
	if (c == '+') return 62;
	if (c == '/') return 63;
	return -1;
}

uint8_t *base64_decode(const char *in, size_t len, size_t *outlen)
{
	if (len % 4) return NULL;
	size_t olen = len / 4 * 3;
	if (len >= 1 && in[len - 1] == '=') olen--;
	if (len >= 2 && in[len - 2] == '=') olen--;

	uint8_t *out = malloc(olen);
	if (!out) return NULL;

	size_t i = 0, j = 0;
	while (i < len) {
		int v0 = b64_inv(in[i++]);
		int v1 = b64_inv(in[i++]);
		int v2 = (in[i] == '=') ? -1 : b64_inv(in[i]);
		i++;
		int v3 = (in[i] == '=') ? -1 : b64_inv(in[i]);
		i++;

		if (v0 < 0 || v1 < 0) { free(out); return NULL; }

		uint32_t triple = (v0 << 18) | (v1 << 12)
						| ((v2 < 0 ? 0 : v2) << 6)
						| ((v3 < 0 ? 0 : v3));

		if (j < olen) out[j++] = (triple >> 16) & 0xFF;
		if (v2 >= 0 && j < olen) out[j++] = (triple >> 8) & 0xFF;
		if (v3 >= 0 && j < olen) out[j++] = triple & 0xFF;
	}
	if (outlen) *outlen = j;
	return out;
}

/* ======== MD5 ======== */
typedef struct {
	uint32_t h[4];
	uint64_t len;
	uint8_t  buf[64];
	size_t   buf_len;
} MD5_CTX;

static void md5_init(MD5_CTX *ctx) {
	ctx->h[0] = 0x67452301;
	ctx->h[1] = 0xefcdab89;
	ctx->h[2] = 0x98badcfe;
	ctx->h[3] = 0x10325476;
	ctx->len = 0;
	ctx->buf_len = 0;
}

static void md5_transform(uint32_t h[4], const uint8_t block[64]) {
	static const uint32_t K[64] = {
		0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
		0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
		0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
		0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
		0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
		0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
		0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
		0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
	};
	static const uint8_t S[64] = {
		7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
		5,9,14,20, 5,9,14,20, 5,9,14,20, 5,9,14,20,
		4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
		6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
	};

	uint32_t a=h[0], b=h[1], c=h[2], d=h[3], f, g, temp;
	uint32_t M[16];
	for (int i=0; i<16; i++)
		M[i] = ((uint32_t)block[i*4]) | ((uint32_t)block[i*4+1]<<8)
			 | ((uint32_t)block[i*4+2]<<16) | ((uint32_t)block[i*4+3]<<24);

	for (int i=0; i<64; i++) {
		if (i<16) { f=(b&c)|((~b)&d); g=i; }
		else if (i<32) { f=(d&b)|((~d)&c); g=(5*i+1)%16; }
		else if (i<48) { f=b^c^d; g=(3*i+5)%16; }
		else { f=c^(b|(~d)); g=(7*i)%16; }
		temp = d;
		d = c;
		c = b;
		b = b + ((a + f + K[i] + M[g]) << S[i] | ((a + f + K[i] + M[g]) >> (32-S[i])));
		a = temp;
	}
	h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d;
}

static void md5_update(MD5_CTX *ctx, const uint8_t *data, size_t len) {
	ctx->len += len*8;
	while (len) {
		size_t copy = 64 - ctx->buf_len;
		if (copy > len) copy = len;
		memcpy(ctx->buf + ctx->buf_len, data, copy);
		ctx->buf_len += copy;
		data += copy;
		len -= copy;
		if (ctx->buf_len == 64) {
			md5_transform(ctx->h, ctx->buf);
			ctx->buf_len = 0;
		}
	}
}

static void md5_final(MD5_CTX *ctx, unsigned char out[16]) {
	size_t i = ctx->buf_len;
	ctx->buf[i++] = 0x80;
	if (i > 56) {
		while (i < 64) ctx->buf[i++] = 0;
		md5_transform(ctx->h, ctx->buf);
		i = 0;
	}
	while (i < 56) ctx->buf[i++] = 0;
	uint64_t bitlen = ctx->len;
	memcpy(ctx->buf + 56, &bitlen, 8);
	md5_transform(ctx->h, ctx->buf);
	for (i = 0; i < 4; i++)
		memcpy(out + i*4, &ctx->h[i], 4);
}

/* ======== SHA-256 ======== */
typedef struct {
	uint32_t h[8];
	uint64_t len;
	uint8_t  buf[64];
} SHA256_CTX;

static uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32-n)); }

static void sha256_init(SHA256_CTX *ctx) {
    static const uint32_t iv[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };
    memcpy(ctx->h, iv, sizeof(iv));
    ctx->len = 0;
    memset(ctx->buf, 0, sizeof(ctx->buf));
}

static void sha256_transform(SHA256_CTX *ctx, const uint8_t data[64]) {
    static const uint32_t K[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };

    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)data[i * 4] << 24)
             | ((uint32_t)data[i * 4 + 1] << 16)
             | ((uint32_t)data[i * 4 + 2] << 8)
             | ((uint32_t)data[i * 4 + 3]);
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >> 3);
        uint32_t s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }

    uint32_t a=ctx->h[0], b=ctx->h[1], c=ctx->h[2], d=ctx->h[3];
    uint32_t e=ctx->h[4], f=ctx->h[5], g=ctx->h[6], h=ctx->h[7];

    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr(e,6)^rotr(e,11)^rotr(e,25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t temp1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0 = rotr(a,2)^rotr(a,13)^rotr(a,22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    ctx->h[0] += a; ctx->h[1] += b; ctx->h[2] += c; ctx->h[3] += d;
    ctx->h[4] += e; ctx->h[5] += f; ctx->h[6] += g; ctx->h[7] += h;
}

static void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len) {
    size_t idx = (ctx->len / 8) % 64;
    ctx->len += (uint64_t)len * 8;
    size_t fill = 64 - idx;

    if (idx && len >= fill) {
        memcpy(ctx->buf + idx, data, fill);
        sha256_transform(ctx, ctx->buf);
        data += fill;
        len  -= fill;
        idx = 0;
    }
    while (len >= 64) {
        sha256_transform(ctx, data);
        data += 64;
        len  -= 64;
    }
    if (len)
        memcpy(ctx->buf + idx, data, len);
}

static void sha256_final(SHA256_CTX *ctx, unsigned char out[32]) {
    size_t idx = (ctx->len / 8) % 64;
    ctx->buf[idx++] = 0x80;

    if (idx > 56) {
        memset(ctx->buf + idx, 0, 64 - idx);
        sha256_transform(ctx, ctx->buf);
        idx = 0;
    }
    memset(ctx->buf + idx, 0, 56 - idx);

    uint64_t bits = ctx->len;
    for (int i = 0; i < 8; i++)
        ctx->buf[63 - i] = bits >> (i * 8);

    sha256_transform(ctx, ctx->buf);

    for (int i = 0; i < 8; i++) {
        out[i*4]   = (ctx->h[i] >> 24) & 0xFF;
        out[i*4+1] = (ctx->h[i] >> 16) & 0xFF;
        out[i*4+2] = (ctx->h[i] >> 8)  & 0xFF;
        out[i*4+3] = ctx->h[i] & 0xFF;
    }
}

/* ======== Unified API ======== */
size_t digest(const uint8_t *data, size_t len, unsigned char **out, enum DigestType type) {
	if (type == DIGEST_MD5) {
		*out = malloc(16);
		MD5_CTX ctx; md5_init(&ctx);
		md5_update(&ctx, data, len);
		md5_final(&ctx, *out);
		return 16;
	} else if (type == DIGEST_SHA256) {
		*out = malloc(32);
		SHA256_CTX ctx; sha256_init(&ctx);
		sha256_update(&ctx, data, len);
		sha256_final(&ctx, *out);
		return 32;
	}
	*out = NULL;
	return 0;
}


static JSValue js_hash_tobase64(JSContext *ctx, JSValueConst this_val,
							   int argc, JSValueConst *argv)
{
	size_t inlen;
	uint8_t *instr = JS_GetArrayBuffer(ctx, &inlen, argv[0]);
	if( !instr )
	{
		JS_ThrowTypeError(ctx, "require input to encode");
		return JS_UNDEFINED;
	}

	size_t outlen;
	char *ptr = base64_encode(instr, inlen, &outlen);
	if( !ptr )
		return JS_ThrowInternalError(ctx, "OOM");

	JSValue js_b64 = JS_NewStringLen(ctx, ptr, outlen);
	free(ptr);

	return js_b64;
}

static JSValue js_hash_frombase64(JSContext *ctx, JSValueConst this_val,
								 int argc, JSValueConst *argv)
{
	size_t len;
	const char *str = JS_ToCStringLen(ctx, &len, argv[0]);
	if (!str)
		return JS_ThrowTypeError(ctx, "Expected string");

	size_t outlen;
	uint8_t *data = base64_decode(str, len, &outlen);
	JS_FreeCString(ctx, str);
	if (!data)
		return JS_ThrowInternalError(ctx, "Invalid Base64");

	JSValue arr = JS_NewArrayBufferCopy(ctx, data, outlen);
	free(data);
	return arr;
}

static JSValue js_digest( JSContext *ctx, JSValueConst this_val,
				int argc, JSValueConst *argv, enum DigestType type
) {
	size_t inlen;
	uint8_t *instr = JS_GetArrayBuffer(ctx, &inlen, argv[0]);
	if( !instr )
	{
		JS_ThrowTypeError(ctx, "require input to digest");
		return JS_UNDEFINED;
	}

	unsigned char *res;
	size_t dlen = digest(instr, inlen, &res, type);

	char hex[dlen * 2 + 1];
	for( size_t i = 0; i < dlen; i++ )
		sprintf( hex + i*2, "%02x", res[i] );
	hex[dlen*2] = '\0';
	free(res);

	JSValue hexDigest = JS_NewString(ctx, hex);
	return hexDigest;
}

static JSValue js_hash_md5sum(JSContext *ctx, JSValueConst this_val,
							 int argc, JSValueConst *argv)
{
	return js_digest( ctx, this_val, argc, argv, DIGEST_MD5 );
}

static JSValue js_hash_sha256sum(JSContext *ctx, JSValueConst this_val,
								int argc, JSValueConst *argv)
{
	return js_digest( ctx, this_val, argc, argv, DIGEST_SHA256 );
}

static JSValue js_hash_arraybuffer_to_string(JSContext *ctx, JSValueConst this_val,
					   int argc, JSValueConst *argv)
{
	if( argc < 1 )
	{
		JS_ThrowTypeError(ctx, "requires uint8array to convert as input");
		return JS_EXCEPTION;
	}

	size_t inlen;
	unsigned char *instr = JS_GetArrayBuffer(ctx, &inlen, argv[0]);
	if( !instr )
	{
		JS_ThrowTypeError(ctx, "require input to convert");
		return JS_EXCEPTION;
	}

	JSValue newstr = JS_NewStringLen(ctx, instr, inlen);
	return newstr;
}

static JSValue js_hash_string_to_arraybuffer(JSContext *ctx, JSValueConst this_val,
					  int argc, JSValueConst *argv)
{
	if( argc < 1 )
	{
		JS_ThrowTypeError(ctx, "requires string to convert as input");
		return JS_EXCEPTION;
	}

	size_t strLen;
	const char *str = JS_ToCStringLen(ctx, &strLen, argv[0]);
	if( !str )
	{
		JS_ThrowTypeError(ctx, "requires a valid string to convert");
		return JS_EXCEPTION;
	}

	JSValue arr = JS_NewArrayBufferCopy(ctx, str, strLen);

	return arr;
}

static const JSCFunctionListEntry js_hash_funcs[] = {
	JS_CFUNC_DEF("toBase64", 1, js_hash_tobase64 ),
	JS_CFUNC_DEF("fromBase64", 1, js_hash_frombase64 ),
	JS_CFUNC_DEF("md5sum", 1, js_hash_md5sum ),
	JS_CFUNC_DEF("sha256sum", 1, js_hash_sha256sum ),
	JS_CFUNC_DEF("arrayBufferToString", 1, js_hash_arraybuffer_to_string ),
	JS_CFUNC_DEF("stringToArrayBuffer", 1, js_hash_string_to_arraybuffer ),
};

static int js_hash_init(JSContext *ctx, JSModuleDef *m)
{
	JS_SetModuleExportList(ctx, m, js_hash_funcs,
						   countof(js_hash_funcs));
	return 0;
}

JSModuleDef *js_init_module(JSContext *ctx, const char *module_name)
{
	JSModuleDef *m = JS_NewCModule(ctx, module_name, js_hash_init);
	if (!m)
		return NULL;

	JS_AddModuleExportList(ctx, m, js_hash_funcs, countof(js_hash_funcs));
	return m;
}

