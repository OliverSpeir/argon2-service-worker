import type { Context } from "hono";

/** In-memory user DB */
const users = new Map<string, string>();

export async function createUser(c: Context<{ Bindings: Env }>) {
  const { username, password } = await c.req.json<{ username?: string; password?: string }>();

  if (!username || !password) {
    return c.json({ error: "username and password required" }, 400);
  }

  if (users.has(username)) {
    return c.json({ error: "user already exists" }, 409);
  }

  const response = await c.env.HASHING.fetch("http://binding/hash_password", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password }),
  });

  if (!response.ok) {
    return new Response(response.body, response);
  }

  const { password_hash } = await response.json<{ password_hash: string }>();
  users.set(username, password_hash);

  return c.json({ ok: true });
}

export async function verifyUser(c: Context<{ Bindings: Env }>) {
  const { username, password } = await c.req.json<{ username?: string; password?: string }>();

  if (!username || !password) {
    return c.json({ error: "username and password required" }, 400);
  }

  const storedHash = users.get(username);
  if (!storedHash) {
    return c.json({ error: "invalid credentials" }, 401);
  }

  const response = await c.env.HASHING.fetch("http://binding/verify_password", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password, hash: storedHash }),
  });

  if (!response.ok) {
    return new Response(response.body, response);
  }

  const { ok } = await response.json<{ ok: boolean }>();
  if (!ok) {
    return c.json({ error: "invalid credentials" }, 401);
  }

  return c.json({ ok: true });
}
