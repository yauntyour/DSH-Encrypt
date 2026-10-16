//#region src/shared/validation/primitives.ts
/** Small validation primitives implemented without regular expressions. */
/** Whether a value is a non-array object. */
function isPlainRecord(value) {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}
/** Whether a value is an ASCII hexadecimal string of the requested length. */
function isAsciiHex(value, length) {
	if (typeof value !== "string" || value.length === 0 || length !== void 0 && value.length !== length) return false;
	for (let index = 0; index < value.length; index += 1) {
		const code = value.charCodeAt(index);
		if (!(code >= 48 && code <= 57) && !(code >= 65 && code <= 70) && !(code >= 97 && code <= 102)) return false;
	}
	return true;
}
/** Whether a value is a lowercase ASCII hexadecimal string of the requested length. */
function isAsciiLowerHex(value, length) {
	if (typeof value !== "string" || value.length === 0 || length !== void 0 && value.length !== length) return false;
	for (let index = 0; index < value.length; index += 1) {
		const code = value.charCodeAt(index);
		if (!(code >= 48 && code <= 57) && !(code >= 97 && code <= 102)) return false;
	}
	return true;
}
/** Whether a value follows the credential-reference grammar. */
function isCredentialReference(value) {
	if (value.length === 0) return false;
	for (let index = 0; index < value.length; index += 1) {
		const code = value.charCodeAt(index);
		const upper = code >= 65 && code <= 90;
		const lower = code >= 97 && code <= 122;
		const underscore = code === 95;
		if (index === 0) {
			if (!upper && !lower && !underscore) return false;
			continue;
		}
		if (!upper && !lower && !underscore && !(code >= 48 && code <= 57)) return false;
	}
	return true;
}
/** Remove repeated trailing instances of one character. */
function trimTrailingCharacter(value, character) {
	if (character.length !== 1) throw new TypeError("character must contain exactly one code unit");
	let end = value.length;
	while (end > 0 && value[end - 1] === character) end -= 1;
	return value.slice(0, end);
}
/**
* Whether a value follows the credential-record key grammar: exactly two
* `/`-joined lowercase hyphenated segments (`scope/id`), the same grammar the
* credential seam's `credentialKey` builds.
*/
function isCredentialKeyName(value) {
	const slash = value.indexOf("/");
	if (slash === -1 || slash !== value.lastIndexOf("/")) return false;
	return isCredentialKeySegment(value.slice(0, slash)) && isCredentialKeySegment(value.slice(slash + 1));
}
/** Whether one credential-key segment is a lowercase hyphenated identifier. */
function isCredentialKeySegment(value) {
	if (value.length === 0) return false;
	for (let index = 0; index < value.length; index += 1) {
		const code = value.charCodeAt(index);
		const lower = code >= 97 && code <= 122;
		const digit = code >= 48 && code <= 57;
		const hyphen = code === 45;
		if (index === 0) {
			if (!lower) return false;
			continue;
		}
		if (!lower && !digit && !hyphen) return false;
	}
	return true;
}
/** Fold CRLF and lone CR line endings into LF. */
function normalizeLineEndings(value) {
	return value.replaceAll("\r\n", "\n").replaceAll("\r", "\n");
}
//#endregion
export { isPlainRecord as a, isCredentialReference as i, isAsciiLowerHex as n, normalizeLineEndings as o, isCredentialKeyName as r, trimTrailingCharacter as s, isAsciiHex as t };

//# sourceMappingURL=primitives-D0BudhaR.js.map