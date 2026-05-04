import { describe, expect, it } from "bun:test";
import {
	hostnameAllowedForDeepLinkApp,
	resolveDeepLink,
} from "./deep-link-apps";

describe("resolveDeepLink", () => {
	it("resolves instagram user deep link for an allowed HTTPS host", () => {
		const uri = resolveDeepLink(
			"instagram",
			"https://instagram.com/someuser"
		);
		expect(uri).toBe("instagram://user?username=someuser");
	});

	it("returns null when HTTPS host does not match the selected deep-link app", () => {
		expect(
			resolveDeepLink("instagram", "https://evil.example/p/some-id")
		).toBeNull();
		expect(
			resolveDeepLink("facebook", "https://evil.com/profile")
		).toBeNull();
	});

	it("returns null for non-http(s) URLs", () => {
		expect(resolveDeepLink("instagram", "javascript:alert(1)")).toBeNull();
	});

	it("returns null for malformed URLs", () => {
		expect(resolveDeepLink("instagram", "")).toBeNull();
		expect(resolveDeepLink("instagram", "not-a-url")).toBeNull();
	});

	it("is case-insensitive on hostname matching", () => {
		expect(
			resolveDeepLink("instagram", "https://WWW.INSTAGRAM.COM/p/abc123")
		).toBe("instagram://media?id=abc123");
	});
});

describe("hostnameAllowedForDeepLinkApp", () => {
	it("matches hostnames case-insensitively", () => {
		const app = {
			color: "",
			hostnames: ["example.com"],
			id: "ex",
			name: "Ex",
			placeholder: "",
			resolveUri: () => null,
			simpleIconSlug: "",
		};
		expect(hostnameAllowedForDeepLinkApp(app, "EXAMPLE.COM")).toBe(true);
		expect(hostnameAllowedForDeepLinkApp(app, "other.com")).toBe(false);
	});
});
