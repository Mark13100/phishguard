
import { test } from "node:test";
import assert from "node:assert/strict";
import { extractUrlFeatures } from "./phishguard-main/extension/engine/urlAnalysis.js";

// T01: A normal HTTPS URL should be parsed correctly.
test("T01 - Normal HTTPS URL", () => {
  const result = extractUrlFeatures("https://example.com");

  assert.equal(result.features.hostname, "example.com");
  assert.equal(result.features.protocol, "https");
});

// T02: Suspicious port should be detected.
test("T02 - Suspicious port detection", () => {
  const result = extractUrlFeatures("https://example.com:8080");

  assert.equal(result.features.port, "8080");
  assert.equal(result.features.hasSuspiciousPort, true);
});

// T03: Invalid IPv4 must not be classified as a valid IP.
test("T03 - Invalid IPv4 address", () => {
  const result = extractUrlFeatures("https://999.999.999.999");

  assert.equal(result.features.isIpAddress, false);
});

// T04: A hexadecimal-looking hostname is not automatically IPv6.
test("T04 - Invalid IPv6 detection", () => {
  const result = extractUrlFeatures("https://deadbeef");

  assert.equal(result.features.isIpAddress, false);
});

test("T04-B - Valid IPv6 address detection", () => {
  const result = extractUrlFeatures("https://[2001:db8::1]");

  assert.equal(result.features.isIpAddress, true);
});


// T05: Uppercase protocol should be normalized correctly.
test("T05 - Uppercase HTTPS protocol", () => {
  const result = extractUrlFeatures("HTTPS://example.com");

  assert.equal(result.features.hostname, "example.com");
  assert.equal(result.features.protocol, "https");
});

// T06: Punycode should be decoded into real Unicode.
test("T06 - Real Punycode decoding", () => {
  const result = extractUrlFeatures("https://xn--bcher-kva.example");

  assert.equal(result.features.isPunycode, true);
  assert.equal(result.features.decodedPunycode, "bücher.example");
});

// T07: Userinfo spoofing should be detected.
test("T07 - Userinfo spoofing", () => {
  const result = extractUrlFeatures(
    "https://paypal.com@evil.com"
  );

  assert.equal(result.features.hostname, "evil.com");
  assert.equal(result.features.hasUserinfo, true);

  assert.ok(
    result.signals.some(
      (signal) => signal.type === "USERINFO_AUTHENTICATION_SPOOF"
    )
  );
});

// T08: Invalid input should not become a fake hostname.
test("T08 - Invalid URL handling", () => {
  const result = extractUrlFeatures("not a valid url");

  assert.equal(result.isValid, false);
});
test("T11 - High-risk TLD detection", () => {
  const result = extractUrlFeatures("https://example.xyz");

  assert.equal(result.features.tld, "xyz");
  assert.equal(result.features.hasHighRiskTld, true);
});

test("T12 - Normal TLD detection", () => {
  const result = extractUrlFeatures("https://example.com");

  assert.equal(result.features.tld, "com");
  assert.equal(result.features.hasHighRiskTld, false);
});

test("T13 - High-risk TLD with subdomain", () => {
  const result = extractUrlFeatures("https://login.example.xyz");

  assert.equal(result.features.tld, "xyz");
  assert.equal(result.features.hasHighRiskTld, true);
});

