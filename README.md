# Argon2id Password Hashing Worker

Cloudflare Worker for secure Argon2id password hashing via service binding.

Parameters: Argon2id v19, 19 MiB memory, 2 iterations, 1 parallelism based on
https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

This service stores directly in DB, maybe not the most modular design. This service only concerns itself with max input size and being constant time, rate limiting normalization etc all need to be handled by the caller. Usernames are stored as provided. This service has no re hash functionality.

If I was to normalize usernames I might do it in the caller and pass both original and normalized username to the service, then store the original in its own column. Or normalize in this service, not sure haven't thought it through.

See https://github.com/glotlabs/argon2-cloudflare for a simliar approach, that just returns the hash or if it matches instead of storing them.

## Setup

1. Create D1 database:

   ```bash
   wrangler d1 create argon2-service-db
   ```

2. Update `wrangler.jsonc` with the database ID (from step 1 output)

3. Run migrations:

   ```bash
   wrangler d1 migrations apply argon2-service-db --remote
   ```

4. Deploy:
   ```bash
   wrangler deploy
   ```

## Usage

```jsonc
// caller's wrangler.jsonc
{
  "services": [{ "binding": "HASHING", "service": "argon2-service" }],
}
```

```typescript
const response = await env.HASHING.fetch("http://binding/create", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ username: "alice", password: "password123" }),
});
```

```typescript
const response = await env.HASHING.fetch("http://binding/verify", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ username: "alice", password: "password123" }),
});
```
