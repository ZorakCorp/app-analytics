const SCRIPT_BLOCK = /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi;
const IFRAME_BLOCK = /<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi;
const OBJECT_BLOCK = /<object\b[^<]*(?:(?!<\/object>)<[^<]*)*<\/object>/gi;
const EMBED_BLOCK = /<embed\b[^>]*>/gi;
const LINK_TAG = /<link\b[^>]*>/gi;
const META_TAG = /<meta\b[^>]*>/gi;

// Remove inline event handlers like onload=, onclick=, etc.
const EVENT_HANDLER_ATTR = /\son[a-z]+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi;

// Remove style attrs (hard to reason about + can be abused for UX spoofing)
const STYLE_ATTR = /\sstyle\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi;

// Neutralize dangerous URL protocols in href/src.
const DANGEROUS_PROTOCOL = /^\s*(?:javascript|data|vbscript)\s*:/i;
const URL_ATTR = /\s(href|src)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi;

/**
 * Best-effort HTML sanitizer for docs CMS content.
 *
 * - Strips obvious active-content tags.
 * - Removes inline event handlers and style attributes.
 * - Neutralizes dangerous href/src protocols.
 *
 * This is intentionally conservative and dependency-free; it's not a full HTML
 * parser, but it blocks the most common XSS vectors for rendered CMS HTML.
 */
export function sanitizeHtmlForDocs(input: string): string {
	let html = input;

	html = html.replaceAll(SCRIPT_BLOCK, "");
	html = html.replaceAll(IFRAME_BLOCK, "");
	html = html.replaceAll(OBJECT_BLOCK, "");
	html = html.replaceAll(EMBED_BLOCK, "");
	html = html.replaceAll(LINK_TAG, "");
	html = html.replaceAll(META_TAG, "");

	html = html.replaceAll(EVENT_HANDLER_ATTR, "");
	html = html.replaceAll(STYLE_ATTR, "");

	html = html.replaceAll(URL_ATTR, (match, attrName, d1, d2, d3) => {
		const raw = String(d1 ?? d2 ?? d3 ?? "");
		if (DANGEROUS_PROTOCOL.test(raw)) {
			return ` ${attrName}="#"`;
		}
		return match;
	});

	return html;
}

