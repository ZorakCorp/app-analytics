/**
 * Denylist scan for high-risk patterns (defense-in-depth; not a full SAST substitute).
 * Runs in CI on Linux; keep rules explainable and avoid noisy heuristics.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..", "..");

const SKIP_DIR_NAMES = new Set([
	"node_modules",
	".git",
	".next",
	"dist",
	".turbo",
	"coverage",
	"storybook-static",
]);

/** Evals package stores model prompts that may mention `eval` verbatim. */
function skipDynamicCodeHeuristics(relPosix: string): boolean {
	return relPosix.startsWith("packages/evals/");
}

function posixRel(absPath: string): string {
	return path.relative(ROOT, absPath).replaceAll("\\", "/");
}

function shouldScanFile(relPosix: string): boolean {
	if (!(relPosix.endsWith(".ts") || relPosix.endsWith(".tsx"))) {
		return false;
	}
	if (
		relPosix.includes(".test.ts") ||
		relPosix.includes(".test.tsx") ||
		relPosix.includes(".spec.ts") ||
		relPosix.includes(".spec.tsx")
	) {
		return false;
	}
	if (
		relPosix.includes("/tests/") ||
		relPosix.includes("/__tests__/") ||
		relPosix.startsWith("packages/test/")
	) {
		return false;
	}
	return true;
}

function walk(absDir: string, out: string[]): void {
	let entries: string[];
	try {
		entries = readdirSync(absDir);
	} catch {
		return;
	}

	for (const name of entries) {
		const abs = path.join(absDir, name);
		let st;
		try {
			st = statSync(abs);
		} catch {
			continue;
		}
		if (st.isDirectory()) {
			if (SKIP_DIR_NAMES.has(name)) {
				continue;
			}
			walk(abs, out);
		} else if (st.isFile()) {
			const rel = posixRel(abs);
			if (shouldScanFile(rel)) {
				out.push(abs);
			}
		}
	}
}

const ORIGIN_TRUE_ALLOWLIST = new Set([
	"apps/api/src/routes/public/index.ts",
]);

interface Violation {
	file: string;
	line: number;
	rule: string;
	snippet: string;
}

function record(
	violations: Violation[],
	file: string,
	line: number,
	rule: string,
	snippet: string
): void {
	violations.push({ file, line, rule, snippet });
}

function scan(): Violation[] {
	const violations: Violation[] = [];
	const files: string[] = [];
	for (const root of ["apps", "packages"]) {
		walk(path.join(ROOT, root), files);
	}

	for (const abs of files) {
		const rel = posixRel(abs);
		let content: string;
		try {
			content = readFileSync(abs, "utf8");
		} catch {
			continue;
		}
		const lines = content.split("\n");
		let i = 0;
		for (const line of lines) {
			i += 1;
			const trimmed = line.trim();
			if (trimmed.startsWith("//") || trimmed.startsWith("*")) {
				continue;
			}

			if (line.includes("$queryRawUnsafe")) {
				record(violations, rel, i, "forbid_$queryRawUnsafe", trimmed);
			}

			if (!skipDynamicCodeHeuristics(rel) && /\beval\s*\(/u.test(line)) {
				record(violations, rel, i, "forbid_eval_call", trimmed);
			}
			if (!skipDynamicCodeHeuristics(rel)) {
				const newFunctionMatch = /\bnew\s+Function\s*\(/u.exec(line);
				if (newFunctionMatch) {
					record(violations, rel, i, "forbid_new_Function", trimmed);
				}
			}

			if (/\borgin:\s*true\b/u.test(line) && !ORIGIN_TRUE_ALLOWLIST.has(rel)) {
				record(violations, rel, i, "cors_origin_true_allowlist_only", trimmed);
			}

			if (/\bdocument\.cookie\s*=/u.test(line)) {
				record(violations, rel, i, "forbid_document_cookie_write", trimmed);
			}
		}
	}

	return violations;
}

const violations = scan();
if (violations.length === 0) {
	process.exit(0);
}

process.stderr.write(
	`${String(violations.length)} security regression violation(s):\n\n${violations
		.map((v) => `${v.file}:${String(v.line)} (${v.rule})\n  ${v.snippet}\n`)
		.join("\n")}\n`
);
process.exit(1);
