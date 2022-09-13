#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/sha.h>
#include <openssl/md5.h>

#include <stdio.h>
#include <string.h>

#include "quickjs-hash.h"
#include "cutils.h"

#define HASH_CHUNKSIZE 512

char *toBase64(const char *strIn, size_t lenIn)
{
	BUF_MEM *bptr;
	BIO *b64, *mem;
	char *ref, *result;
	int bc;

	if( 0 == lenIn )
		lenIn = strlen(strIn);
	
	b64 = BIO_new(BIO_f_base64());
	mem = BIO_new(BIO_s_mem());

	BIO_push(b64, mem);
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	for( size_t offset=0; offset < lenIn; offset += HASH_CHUNKSIZE )
	{
		size_t tot = lenIn - offset;
		if( tot > HASH_CHUNKSIZE )
			tot = HASH_CHUNKSIZE;

		BIO_write(b64, strIn + offset, tot);
	}

	BIO_flush(b64);
	BIO_flush(mem);

	bc = BIO_get_mem_data(mem, &ref);
	result = strndup(ref, bc);

	BIO_free(b64);
	BIO_free(mem);

	return result;
}

size_t fromBase64(const char *strIn, size_t lenIn, uint8_t **out)
{
	BUF_MEM *bptr;
	BIO *b64, *imem;

	size_t bufSize=0, bc=0, r;
	uint8_t *result=NULL;

	if( lenIn == 0 )
		lenIn = strlen(strIn);

	b64 = BIO_new(BIO_f_base64());
	imem = BIO_new_mem_buf(strIn, lenIn);

	BIO_push(b64, imem);
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	do {
		if( bufSize - bc < HASH_CHUNKSIZE )
		{
			bufSize += HASH_CHUNKSIZE;
			result = realloc( result, bufSize );
		}
		r = BIO_read(b64, result+bc, HASH_CHUNKSIZE);

		if( r >= 0 )
			bc += r;
	} while(r > 0);

	BIO_flush(b64);
	BIO_flush(imem);

	BIO_free(b64);
	BIO_free(imem);

	*out = result;

	return bc;
}

size_t digest(const char *strIn, size_t lenIn, unsigned char **out, const EVP_MD *md)
{
	unsigned int md_len = EVP_MAX_MD_SIZE;

	EVP_MD_CTX *ctx = EVP_MD_CTX_new();

	*out = malloc(EVP_MAX_MD_SIZE);

	EVP_DigestInit_ex(ctx, md, NULL);
	for( size_t offset=0; offset < lenIn; offset += HASH_CHUNKSIZE )
	{
		size_t tot = lenIn - offset;
		if( tot > HASH_CHUNKSIZE )
			tot = HASH_CHUNKSIZE;

		EVP_DigestUpdate(ctx, strIn+offset, tot);
	}
	EVP_DigestFinal_ex(ctx, *out, &md_len);

	EVP_MD_CTX_free(ctx);

	return md_len;
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

	char *ptr = toBase64(instr, inlen);
	JSValue js_b64 = JS_NewString(ctx, ptr);
	free(ptr);

	return js_b64;
}

static JSValue js_hash_frombase64(JSContext *ctx, JSValueConst this_val,
                                 int argc, JSValueConst *argv)
{
	size_t inlen;
	int outlen;
	uint8_t *ptr;
	const char *instr = JS_ToCStringLen(ctx, &inlen, argv[0]);
	if( !instr )
	{
		JS_ThrowTypeError(ctx, "require input to decode");
		return JS_UNDEFINED;
	}

	outlen = fromBase64(instr, inlen, &ptr);
	JS_FreeCString(ctx, instr);

	JSValue arr = JS_NewArray(ctx);
	for( int x=0; x < outlen; x++ )
	{
		JSValue val = JS_NewInt32(ctx, ptr[x]);
		JS_SetPropertyUint32(ctx, arr, x, val);
	}
	free(ptr);

	return arr;
}

static JSValue js_digest( JSContext *ctx, JSValueConst this_val,
		        int argc, JSValueConst *argv,
			const EVP_MD *md
) {
	size_t inlen;
	uint8_t *instr = JS_GetArrayBuffer(ctx, &inlen, argv[0]);
	if( !instr )
	{
		JS_ThrowTypeError(ctx, "require input to digest");
		return JS_UNDEFINED;
	}

	unsigned char *res;
	size_t digestLen = digest(instr, inlen, &res, md);

	char asHex[ digestLen * 2 + 1 ];
	memset(asHex, 0, sizeof(asHex));

	int cursor = 0;
	for(int i = 0; i < digestLen; i++)
		cursor += sprintf(&asHex[cursor], "%02x", res[i]);
	free(res);

	JSValue hexDigest = JS_NewString(ctx, asHex);
	return hexDigest;
}

static JSValue js_hash_md5sum(JSContext *ctx, JSValueConst this_val,
                             int argc, JSValueConst *argv)
{
	return js_digest( ctx, this_val, argc, argv, EVP_md5() );
}

static JSValue js_hash_sha256sum(JSContext *ctx, JSValueConst this_val,
                                int argc, JSValueConst *argv)
{
	return js_digest( ctx, this_val, argc, argv, EVP_sha256() );
}

static const JSCFunctionListEntry js_hash_funcs[] = {
    JS_CFUNC_DEF("toBase64", 1, js_hash_tobase64 ),
    JS_CFUNC_DEF("fromBase64", 1, js_hash_frombase64 ),
    JS_CFUNC_DEF("md5sum", 1, js_hash_md5sum ),
    JS_CFUNC_DEF("sha256sum", 1, js_hash_sha256sum ),
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

