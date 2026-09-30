# metafetch

Extracts page metadata (title, description, image, favicon, etc.) from a URL. Built with Next.js API routes.

## `GET /api/title?url=<url>`

All responses share one envelope: `{ "success": true, "data": {...} }` on success, `{ "success": false, "error": { "code", "message" } }` on failure.

### Success — `200`

```json
{
  "success": true,
  "data": {
    "url": "https://example.com/",
    "blocked_waf": false,
    "title": "Example Domain",
    "description": "",
    "image": "https://example.com/og.png",
    "site_name": "example.com",
    "favicon": "https://example.com/favicon.ico",
    "language": "en"
  }
}
```

### Blocked by WAF/anti-bot protection — `200`

Some sites (behind Cloudflare, Akamai, Imperva/Incapsula, Sucuri, AWS WAF, etc.) return a challenge/block page instead of real content. In that case the request still succeeds, but metadata could not be read — treat this as "unknown", not "safe":

```json
{
  "success": true,
  "data": {
    "url": "https://example.com/",
    "blocked_waf": true,
    "message": "site is protected by a WAF/anti-bot challenge; metadata could not be read automatically"
  }
}
```

### Errors

```json
{
  "success": false,
  "error": {
    "code": "INVALID_URL",
    "message": "invalid url"
  }
}
```

| status | code                        | meaning                                        |
| ------ | --------------------------- | ----------------------------------------------- |
| 400    | `INVALID_URL`               | missing/malformed `url` param                   |
| 400    | `DISALLOWED_HOST`           | resolves to a private/internal address (SSRF)   |
| 415    | `UNSUPPORTED_CONTENT_TYPE`  | response content-type isn't HTML                |
| 429    | `RATE_LIMITED`              | rate limited                                    |
| 502    | `UPSTREAM_ERROR`            | upstream request failed / non-2xx               |
| 504    | `TIMEOUT`                   | upstream took longer than 10s                   |

## Notes

- Only `http`/`https` URLs are accepted; hostnames resolving to private, loopback, or link-local addresses are rejected.
- Response HTML charset is auto-detected from the `Content-Type` header or `<meta charset>` tag.
- Rate limiting is best-effort (in-memory per serverless instance); use an external store (e.g. Upstash Redis) if you need a hard global limit.
