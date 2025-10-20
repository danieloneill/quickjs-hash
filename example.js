import * as hash from "hash.so";
import * as std from "std";

function runTests()
{
	const testString = 'Well I met an old man dying on a train. No more destination, no more pain. Well he said one thing: "Before I graduate never let your fear decide your fate"';
	
	const data = hash.stringToArrayBuffer(testString);
	console.log(`Original: ${testString}`);
	console.log(`Uint8Array: ${data}`);
	
	const asB64 = hash.toBase64(data);
	console.log(`Base64 => ${asB64}`);
	
	const fromB64 = hash.fromBase64(asB64);
	console.log(`Base64 <= ${hash.arrayBufferToString(fromB64)}`);
	
	const md5sum = hash.md5sum(data);
	console.log(`MD5 should be bdc20bf28ed988c221cb6cfa2b417b08, got ${md5sum}`);
	
	const sha256sum = hash.sha256sum(data);
	console.log(`SHA256 should be 4a4c36949311dfbe0cae22f498e0e4d7b714a38392681e8aff5620721aa6d98e, got ${sha256sum}`);
}

runTests();

std.gc();

std.exit(0);
