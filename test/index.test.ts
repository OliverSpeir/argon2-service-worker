import { describe, it, expect } from "vitest";
import { SELF } from "cloudflare:test";

describe("argon2 service", () => {
  describe("POST /hash_password", () => {
    it("returns a PHC-formatted hash", async () => {
      const response = await SELF.fetch("http://localhost/hash_password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: "test-password" }),
      });

      expect(response.status).toBe(200);
      const body = await response.json<{ password_hash: string }>();
      expect(body.password_hash).toMatch(/^\$argon2id\$/);
    });

    it("returns error for empty password", async () => {
      const response = await SELF.fetch("http://localhost/hash_password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: "" }),
      });

      expect(response.status).toBe(400);
      const body = await response.json<{ error: string }>();
      expect(body.error).toBe("empty_password");
    });

    it("returns 400 for missing password", async () => {
      const response = await SELF.fetch("http://localhost/hash_password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });

      expect(response.status).toBe(400);
    });
  });

  describe("POST /verify_password", () => {
    it("returns ok true for correct password", async () => {
      const hashResponse = await SELF.fetch("http://localhost/hash_password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: "my-secret" }),
      });
      const { password_hash } = await hashResponse.json<{ password_hash: string }>();

      const verifyResponse = await SELF.fetch("http://localhost/verify_password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: "my-secret", hash: password_hash }),
      });

      expect(verifyResponse.status).toBe(200);
      const body = await verifyResponse.json<{ ok: boolean }>();
      expect(body.ok).toBe(true);
    });

    it("returns ok false for incorrect password", async () => {
      const hashResponse = await SELF.fetch("http://localhost/hash_password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: "correct-password" }),
      });
      const { password_hash } = await hashResponse.json<{ password_hash: string }>();

      const verifyResponse = await SELF.fetch("http://localhost/verify_password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: "wrong-password", hash: password_hash }),
      });

      expect(verifyResponse.status).toBe(200);
      const body = await verifyResponse.json<{ ok: boolean }>();
      expect(body.ok).toBe(false);
    });

    it("returns error for invalid hash format", async () => {
      const response = await SELF.fetch("http://localhost/verify_password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: "test", hash: "not-a-valid-hash" }),
      });

      expect(response.status).toBe(400);
      const body = await response.json<{ error: string }>();
      expect(body.error).toBe("invalid_hash");
    });

    it("returns error for empty password", async () => {
      const response = await SELF.fetch("http://localhost/verify_password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: "", hash: "$argon2id$..." }),
      });

      expect(response.status).toBe(400);
      const body = await response.json<{ error: string }>();
      expect(body.error).toBe("empty_password");
    });

    it("returns error for empty hash", async () => {
      const response = await SELF.fetch("http://localhost/verify_password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: "test", hash: "" }),
      });

      expect(response.status).toBe(400);
      const body = await response.json<{ error: string }>();
      expect(body.error).toBe("empty_hash");
    });
  });

  describe("other routes", () => {
    it("returns 404 for unknown paths", async () => {
      const response = await SELF.fetch("http://localhost/unknown");
      expect(response.status).toBe(404);
    });

    it("returns 404 for GET /hash_password", async () => {
      const response = await SELF.fetch("http://localhost/hash_password");
      expect(response.status).toBe(404);
    });
  });
});
