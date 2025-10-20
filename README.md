# quickjs-hash
Simple base64 encoding and md5/sha256 hashing module for QuickJS

Building requires editing the Makefile and pointing it to your quickjs-2025-09-13 directory.

See **example.js** for usage.

Consists of only 6 methods:
 * toBase64
 * fromBase64
 * md5sum
 * sha256sum
 * arrayBufferToString
 * stringToArrayBuffer

Each method accepts one parameter.

*toBase64*, *md5sum*, and *sha256sum* expect an ArrayBuffer as the only parameter.

*toBase64* returns a string containing the Base64 encoded data.

*md5sum* and *sha256sum* return a hex-encoded string representing the calculated hash of the contents passed.

*fromBase64* expects a string as the only parameter and returns an ArrayBuffer object.

*arrayBufferToString* expects an ArrayBuffer object as a parameter, and returns a string if possible.

*stringToArrayBuffer* expects a string as a parameter, and returns an ArrayBuffer if possible.

Feature requests and PRs are welcome. Also check out my [low-level sockets module](https://github.com/danieloneill/quickjs-net) and [wolfssl module](https://github.com/danieloneill/quickjs-wolfssl).

