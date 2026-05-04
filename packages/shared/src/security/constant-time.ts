const HEX_PAIR = /^[0-9a-f]{2}$/i;

function hexToBytes(hex: string): Uint8Array | null {
	const normalized = hex.trim();
	if (normalized.length === 0 || normalized.length % 2 !== 0) {
		return null;
	}
	const out = new Uint8Array(normalized.length / 2);
	for (let i = 0; i < out.length; i += 1) {
		const pair = normalized.slice(i * 2, i * 2 + 2);
		if (!HEX_PAIR.test(pair)) {
			return null;
		}
		out[i] = Number.parseInt(pair, 16);
	}
	return out;
}

function constantTimeEqualBytes(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) {
		return false;
	}
	let diff = 0;
	for (let i = 0; i < a.length; i += 1) {
		diff |= a[i] ^ b[i];
	}
	return diff === 0;
}

/**
 * Constant-time compare for hex strings (best-effort).
 *
 * - Rejects invalid hex.
 * - Compares decoded bytes in constant-time when lengths match.
 */
export function timingSafeEqualHex(expectedHex: string, providedHex: string): boolean {
	const expected = hexToBytes(expectedHex);
	const provided = hexToBytes(providedHex);
	if (!expected || !provided) {
		return false;
	}
	return constantTimeEqualBytes(expected, provided);
}

