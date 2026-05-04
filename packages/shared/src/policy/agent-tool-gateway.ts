import {
	AGENT_SQL_VALIDATION_ERROR,
	requiresTenantFilter,
	validateAgentSQL,
} from "@databuddy/db/clickhouse";
import { validateUrl } from "../ssrf-guard";

/** Thrown when a server-side agent tool violates central policy gates. */
export class ToolPolicyRejectedError extends Error {
	readonly policyCode = "TOOL_POLICY_REJECTED";

	constructor(message: string) {
		super(message);
		this.name = "ToolPolicyRejectedError";
	}
}

/** Central gate for Agent / MCP ClickHouse SQL tool calls. */
export function assertAgentClickHouseSqlPolicy(sql: string): void {
	const validation = validateAgentSQL(sql);
	if (!validation.valid) {
		throw new ToolPolicyRejectedError(
			validation.reason ?? AGENT_SQL_VALIDATION_ERROR
		);
	}
	if (!requiresTenantFilter(sql)) {
		throw new ToolPolicyRejectedError(
			"Query must include tenant isolation: WHERE client_id = {websiteId:String}"
		);
	}
}

/**
 * SSRF gate for outbound HTTP(S) URLs (image proxy, future fetch proxies).
 */
export async function assertSsrfProtectedHttpUrl(url: string): Promise<{
	safe: true;
	hostname: string;
}> {
	const check = await validateUrl(url);
	if (!check.safe) {
		throw new ToolPolicyRejectedError(check.error ?? "URL not allowed");
	}
	return { safe: true, hostname: check.hostname };
}
