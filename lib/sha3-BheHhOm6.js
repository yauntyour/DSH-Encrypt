import { createHash } from "node:crypto";
//#region src/shared/crypto/keccak.ts
/**
* Pure-JS SHA3-256 (Keccak-f[1600], padding 0x06) over bytes.
*
* One implementation serves both halves of the plugin: the browser client
* hashes the password here (no WebCrypto SHA3), and the node half falls back
* to it when `node:crypto` lacks "sha3-256" — the dsh desktop host runs on
* Electron, whose BoringSSL rejects the algorithm with "Digest method not
* supported". Both must produce byte-identical digests to `node:crypto`.
* @module dsh-encrypt/shared/crypto/keccak
*/
const KECCAK_RC = [
	1n,
	32898n,
	9223372036854808714n,
	9223372039002292224n,
	32907n,
	2147483649n,
	9223372039002292353n,
	9223372036854808585n,
	138n,
	136n,
	2147516425n,
	2147483658n,
	2147516555n,
	9223372036854775947n,
	9223372036854808713n,
	9223372036854808579n,
	9223372036854808578n,
	9223372036854775936n,
	32778n,
	9223372039002259466n,
	9223372039002292353n,
	9223372036854808704n,
	2147483649n,
	9223372039002292232n
];
const KECCAK_RHO = [
	0,
	1,
	62,
	28,
	27,
	36,
	44,
	6,
	55,
	20,
	3,
	10,
	43,
	25,
	39,
	41,
	45,
	15,
	21,
	8,
	18,
	2,
	61,
	56,
	14
];
const KECCAK_PI = [
	0,
	10,
	20,
	5,
	15,
	16,
	1,
	11,
	21,
	6,
	7,
	17,
	2,
	12,
	22,
	23,
	8,
	18,
	3,
	13,
	14,
	24,
	9,
	19,
	4
];
const MASK64 = (1n << 64n) - 1n;
/** SHA3-256 sponge rate in bytes (1600 − 2×256 bits). */
const SHA3_256_RATE = 136;
/**
* Raw 32-byte SHA3-256 digest of the input.
* @param {Uint8Array} input - the bytes to hash.
* @returns {Uint8Array} the 32-byte digest.
*/
function keccakSha3_256(input) {
	const padded = new Uint8Array(Math.ceil((input.length + 1) / SHA3_256_RATE) * SHA3_256_RATE);
	padded.set(input);
	padded[input.length] = 6;
	padded[padded.length - 1] = valueAt(padded, padded.length - 1) | 128;
	let state = Array.from({ length: 25 }).fill(0n);
	for (let offset = 0; offset < padded.length; offset += SHA3_256_RATE) {
		for (let index = 0; index < SHA3_256_RATE; index += 8) {
			let word = 0n;
			for (let byte = 0; byte < 8; byte += 1) word |= BigInt(valueAt(padded, offset + index + byte)) << BigInt(8 * byte);
			state[index / 8] = valueAt(state, index / 8) ^ word;
		}
		state = keccakF(state);
	}
	const output = /* @__PURE__ */ new Uint8Array(32);
	for (let index = 0; index < 4; index += 1) {
		let word = valueAt(state, index);
		for (let byte = 0; byte < 8; byte += 1) {
			output[index * 8 + byte] = Number(word & 255n);
			word >>= 8n;
		}
	}
	return output;
}
function keccakF(lanes) {
	for (let round = 0; round < 24; round += 1) {
		const columns = [];
		for (let x = 0; x < 5; x += 1) columns[x] = valueAt(lanes, x) ^ valueAt(lanes, x + 5) ^ valueAt(lanes, x + 10) ^ valueAt(lanes, x + 15) ^ valueAt(lanes, x + 20);
		const deltas = [];
		for (let x = 0; x < 5; x += 1) deltas[x] = valueAt(columns, (x + 4) % 5) ^ rotateLeft(valueAt(columns, (x + 1) % 5), 1);
		for (let x = 0; x < 5; x += 1) for (let y = 0; y < 5; y += 1) {
			const index = x + 5 * y;
			lanes[index] = valueAt(lanes, index) ^ valueAt(deltas, x);
		}
		const rotated = Array.from({ length: 25 }).fill(0n);
		for (let index = 0; index < 25; index += 1) rotated[valueAt(KECCAK_PI, index)] = rotateLeft(valueAt(lanes, index), valueAt(KECCAK_RHO, index));
		for (let x = 0; x < 5; x += 1) for (let y = 0; y < 5; y += 1) {
			const index = x + 5 * y;
			lanes[index] = valueAt(rotated, index) ^ ~valueAt(rotated, (x + 1) % 5 + 5 * y) & valueAt(rotated, (x + 2) % 5 + 5 * y);
		}
		lanes[0] = valueAt(lanes, 0) ^ valueAt(KECCAK_RC, round);
	}
	return lanes;
}
function rotateLeft(value, offset) {
	return (value << BigInt(offset) | value >> BigInt(64 - offset)) & MASK64;
}
function valueAt(values, index) {
	const value = values[index];
	if (value === void 0) throw new RangeError(`index ${index} is outside an array of length ${values.length}`);
	return value;
}
//#endregion
//#region src/infrastructure/crypto/sha3.ts
/**
* Node-side SHA3-256 with a pure-JS fallback.
*
* Real Node links OpenSSL, which provides "sha3-256". The dsh desktop host
* runs inside Electron (BoringSSL), where `createHash('sha3-256')` throws
* "Digest method not supported"; there every digest falls back to the pure-JS
* Keccak shared with the browser half, so fingerprints, verifiers and the
* shipped-file integrity check keep working instead of failing the import.
* The capability is probed once at module load; both paths are byte-identical.
* @module dsh-encrypt/infrastructure/crypto/sha3
*/
/** The native SHA3-256 hasher, or `undefined` when the runtime lacks one. */
const nativeSha3 = (() => {
	try {
		createHash("sha3-256").update("").digest();
		return (input) => createHash("sha3-256").update(input).digest();
	} catch {
		return;
	}
})();
/**
* Raw 32-byte SHA3-256 digest of the input.
* @param {Uint8Array} input - the bytes to hash.
* @returns {Buffer} the 32-byte digest.
*/
function sha3_256Bytes(input) {
	return nativeSha3 === void 0 ? Buffer.from(keccakSha3_256(input)) : nativeSha3(input);
}
/**
* Lowercase hex SHA3-256 of UTF-8 text.
* @param {string} text - the text to hash.
* @returns {string} the 64-character lowercase hex digest.
*/
function sha3_256Hex(text) {
	return sha3_256Bytes(Buffer.from(text, "utf8")).toString("hex");
}
/**
* Lowercase hex SHA3-256 of the input bytes.
* @param {Uint8Array} input - the bytes to hash.
* @returns {string} the 64-character lowercase hex digest.
*/
function sha3_256HexOfBytes(input) {
	return sha3_256Bytes(input).toString("hex");
}
//#endregion
export { sha3_256Hex as n, sha3_256HexOfBytes as r, sha3_256Bytes as t };

//# sourceMappingURL=sha3-BheHhOm6.js.map