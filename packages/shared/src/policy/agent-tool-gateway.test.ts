import { describe, expect, it } from "bun:test";
import {
	assertAgentClickHouseSqlPolicy,
	assertSsrfProtectedHttpUrl,
	ToolPolicyRejectedError,
} from "./agent-tool-gateway";

describe("assertAgentClickHouseSqlPolicy", () => {
	it("rejects SQL without tenant isolation", () => {
		expect(() => assertAgentClickHouseSqlPolicy("SELECT 1")).toThrow(
			ToolPolicyRejectedError
		);
	});
});

describe("assertSsrfProtectedHttpUrl", () => {
	it("rejects javascript: URLs", async () => {
		await expect(
			assertSsrfProtectedHttpUrl("javascript:alert(1)")
		).rejects.toBeInstanceOf(ToolPolicyRejectedError);
	});
});
