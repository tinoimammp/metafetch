# metafetch

Extracts page metadata (title, description, image, favicon, etc.) from a URL. Built with Next.js API routes.

## `GET /api/title?url=<url>`

### Success — `200`

```json
{
  "url": "https://example.com/",
  "title": "Example Domain",
  "description": "",
  "image": "https://example.com/og.png",
  "siteName": "example.com",
  "favicon": "https://example.com/favicon.ico",
  "language": "en"
}
```

### Errors

| status | msg                                   | meaning                                      |
| ------ | -------------------------------------- | --------------------------------------------- |
| 400    | `invalid url`                          | missing/malformed `url` param                 |
| 400    | `url points to a disallowed host`      | resolves to a private/internal address (SSRF) |
| 415    | `url does not point to an html page`   | response content-type isn't HTML              |
| 429    | `too many requests, please slow down`  | rate limited                                  |
| 502    | `failed to fetch url`                  | upstream request failed / non-2xx             |
| 504    | `request to url timed out`             | upstream took longer than 10s                 |

## Notes

- Only `http`/`https` URLs are accepted; hostnames resolving to private, loopback, or link-local addresses are rejected.
- Response HTML charset is auto-detected from the `Content-Type` header or `<meta charset>` tag.
- Rate limiting is best-effort (in-memory per serverless instance); use an external store (e.g. Upstash Redis) if you need a hard global limit.
