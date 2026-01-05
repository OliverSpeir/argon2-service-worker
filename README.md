# Argon2id Password Hashing Worker

Cloudflare Worker for secure Argon2id password hashing via service binding. Inspired by [glotlabs/argon2-cloudflare](https://github.com/glotlabs/argon2-cloudflare).

Parameters: Argon2id v19, 19 MiB memory, 2 iterations, 1 parallelism based on
https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

## API

### POST /hash_password

Hash a password, returning the PHC-formatted hash string.

Request:
```json
{"password": "my-secret"}
```

Response:
```json
{"password_hash": "$argon2id$v=19$m=19456,t=2,p=1$..."}
```

### POST /verify_password

Verify a password against a PHC-formatted hash string.

Request:
```json
{"password": "my-secret", "hash": "$argon2id$v=19$m=19456,t=2,p=1$..."}
```

Response:
```json
{"ok": true}
```

### Errors

All errors return JSON with an appropriate status code:

```json
{"error": "password_too_long"}
```

| Error | Status | Description |
|-------|--------|-------------|
| `empty_password` | 400 | Password is empty |
| `password_too_long` | 400 | Password exceeds 2048 bytes |
| `empty_hash` | 400 | Hash is empty |
| `hash_too_long` | 400 | Hash exceeds 2048 bytes |
| `invalid_hash` | 400 | Hash is not valid PHC format |
| `internal_error` | 500 | Hashing failed |

## Setup

1. Deploy:
   ```bash
   wrangler deploy
   ```

## Usage

```jsonc
// caller's wrangler.jsonc
{
  "services": [{ "binding": "ARGON2", "service": "argon2-service" }]
}
```

```typescript
// Hash a password
const hashResponse = await env.ARGON2.fetch("http://internal/hash_password", {
  method: "POST",
  body: JSON.stringify({ password: "password123" }),
});
const { password_hash } = await hashResponse.json();

// Verify a password
const verifyResponse = await env.ARGON2.fetch("http://internal/verify_password", {
  method: "POST",
  body: JSON.stringify({ password: "password123", hash: password_hash }),
});
const { ok } = await verifyResponse.json();
```
