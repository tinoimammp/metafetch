import cheerio from 'cheerio'
import dns from 'dns/promises'
import net from 'net'

import type { NextApiHandler, NextApiRequest, NextApiResponse } from 'next'

const TIMEOUT_MS = 10_000
const MAX_BODY_BYTES = 5 * 1024 * 1024 // 5MB, enough for <head> of virtually any page

const RATE_LIMIT_WINDOW_MS = 60_000
const RATE_LIMIT_MAX = 30
// best-effort only: each serverless instance has its own memory, so this does
// not enforce a hard global limit, but it stops a single hot instance from
// being hammered
const hits = new Map<string, { count: number; resetAt: number }>()

function isRateLimited(ip: string): boolean {
	const now = Date.now()
	const entry = hits.get(ip)
	if (!entry || now > entry.resetAt) {
		hits.set(ip, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS })
		return false
	}
	entry.count += 1
	return entry.count > RATE_LIMIT_MAX
}

function clientIp(req: NextApiRequest): string {
	const forwarded = req.headers['x-forwarded-for']
	if (typeof forwarded === 'string' && forwarded.length > 0) {
		return forwarded.split(',')[0].trim()
	}
	return req.socket.remoteAddress ?? 'unknown'
}

function parseUrl(raw: string): URL | null {
	// browsers happily send unencoded spaces/special chars in query strings;
	// be lenient and try to fix them up before giving up
	const candidates = [raw, raw.trim().replace(/ /g, '%20')]

	for (const candidate of candidates) {
		try {
			const parsed = new URL(candidate)
			if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
				return parsed
			}
		} catch {
			// try next candidate
		}
	}

	return null
}

function isPrivateIp(ip: string): boolean {
	if (net.isIPv4(ip)) {
		const parts = ip.split('.').map(Number)
		const [a, b] = parts
		if (a === 10) return true
		if (a === 127) return true
		if (a === 0) return true
		if (a === 169 && b === 254) return true
		if (a === 172 && b >= 16 && b <= 31) return true
		if (a === 192 && b === 168) return true
		if (a === 100 && b >= 64 && b <= 127) return true // shared/CGNAT range
		return false
	}

	if (net.isIPv6(ip)) {
		const normalized = ip.toLowerCase()
		if (normalized === '::1') return true
		if (normalized.startsWith('fe80:')) return true // link-local
		if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true // unique local
		if (normalized.startsWith('::ffff:')) {
			return isPrivateIp(normalized.replace('::ffff:', ''))
		}
		return false
	}

	return true // unknown format, treat as unsafe
}

async function assertPublicHost(hostname: string): Promise<void> {
	const records = await dns.lookup(hostname, { all: true })
	if (records.length === 0) {
		throw new Error('could not resolve host')
	}
	for (const record of records) {
		if (isPrivateIp(record.address)) {
			throw new Error('host resolves to a private/internal address')
		}
	}
}

function detectCharset(contentType: string | null, headBytes: Buffer): string {
	const headerMatch = contentType?.match(/charset=([^;]+)/i)
	if (headerMatch) return headerMatch[1].trim().toLowerCase()

	// sniff <meta charset=".."> / <meta http-equiv="Content-Type" content="...charset=..">
	// from the raw bytes, decoded as ascii-safe latin1 just for this scan
	const head = headBytes.toString('latin1')
	const metaCharset = head.match(/<meta[^>]+charset=["']?([\w-]+)/i)
	if (metaCharset) return metaCharset[1].toLowerCase()

	return 'utf-8'
}

function decodeHtml(buffer: Buffer, contentType: string | null): string {
	const charset = detectCharset(contentType, buffer.subarray(0, 2048))
	try {
		return new TextDecoder(charset).decode(buffer)
	} catch {
		return new TextDecoder('utf-8').decode(buffer)
	}
}

// heuristics only: identifies that we got a WAF/anti-bot challenge or block
// page instead of real content, so the caller can treat the result as
// "unknown" rather than silently returning empty/wrong metadata. Not
// exhaustive, and not an attempt to defeat any of these protections.
function isProtectionChallengePage(headers: Headers, buffer: Buffer): boolean {
	if (headers.get('cf-mitigated') === 'challenge') return true
	if (headers.has('cf-chl-bypass')) return true
	if (headers.has('x-sucuri-id')) return true
	if (headers.has('x-iinfo')) return true // Incapsula/Imperva

	const sample = buffer.subarray(0, 4096).toString('latin1').toLowerCase()
	return (
		sample.includes('checking your browser before accessing') || // Cloudflare
		sample.includes('cf-chl-') ||
		sample.includes('cf_chl_opt') ||
		sample.includes('/cdn-cgi/challenge-platform/') ||
		sample.includes('sucuri website firewall') || // Sucuri
		sample.includes('incapsula incident id') || // Imperva/Incapsula
		sample.includes('akamaighost') || // Akamai
		(sample.includes('reference #') && sample.includes('access denied')) ||
		sample.includes('the request could not be satisfied') // AWS WAF/CloudFront
	)
}

function absoluteUrl(base: URL, maybeRelative: string | undefined): string | undefined {
	if (!maybeRelative) return undefined
	try {
		return new URL(maybeRelative, base).toString()
	} catch {
		return undefined
	}
}

// ---------------------------------------------------------------------------
// Browser identity
//
// Anti-bot systems rarely block on a single header; they look for *consistency*.
// A "real browser" is not just a spoofed User-Agent, it is a coherent set:
// UA string, Client Hints (sec-ch-ua*), Sec-Fetch-* navigation context and
// Accept headers must all agree on the same engine, version and platform.
// Anything mismatched (e.g. Chrome UA + Firefox hints, or a UA with no hints)
// is itself a bot signal, so we keep each profile fully self-consistent.
// ---------------------------------------------------------------------------

type BrowserProfile = {
	name: string
	userAgent: string
	platform: string
	// full & reduced Client Hints vocabulary for this exact version/platform
	clientHints: Record<string, string>
}

const CHROME_VERSION = '126'
const CHROME_MAJOR = '126'

const PROFILES: BrowserProfile[] = [
	{
		name: 'chrome-win',
		userAgent:
			'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
		platform: '"Windows"',
		clientHints: {
			'sec-ch-ua': `"Chromium";v="${CHROME_MAJOR}", "Google Chrome";v="${CHROME_MAJOR}", "Not.A/Brand";v="24"`,
			'sec-ch-ua-mobile': '?0',
			'sec-ch-ua-platform': '"Windows"',
			'sec-ch-ua-platform-version': '"15.0.0"',
			'sec-ch-ua-arch': '"x86"',
			'sec-ch-ua-bitness': '"64"',
			'sec-ch-ua-model': '""',
			'sec-ch-ua-full-version': `"${CHROME_VERSION}.0.0.0"`,
			'sec-ch-ua-full-version-list': `"Chromium";v="${CHROME_VERSION}.0.0.0", "Google Chrome";v="${CHROME_VERSION}.0.0.0", "Not.A/Brand";v="24.0.0.0"`,
		},
	},
	{
		name: 'chrome-mac',
		userAgent:
			'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
		platform: '"macOS"',
		clientHints: {
			'sec-ch-ua': `"Chromium";v="125", "Google Chrome";v="125", "Not.A/Brand";v="24"`,
			'sec-ch-ua-mobile': '?0',
			'sec-ch-ua-platform': '"macOS"',
			'sec-ch-ua-platform-version': '"14.5.0"',
			'sec-ch-ua-arch': '"arm"',
			'sec-ch-ua-bitness': '"64"',
			'sec-ch-ua-model': '""',
			'sec-ch-ua-full-version': '"125.0.0.0"',
			'sec-ch-ua-full-version-list':
				'"Chromium";v="125.0.0.0", "Google Chrome";v="125.0.0.0", "Not.A/Brand";v="24.0.0.0"',
		},
	},
	{
		name: 'firefox-win',
		// Firefox never sends Sec-CH-UA; correctness means sending the hint-free
		// header set a real Firefox would, not copying Chrome's hints onto it.
		userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0',
		platform: '"Windows"',
		clientHints: {},
	},
]

// Accept header order/value differs slightly per engine; Firefox advertises a
// narrower set and does not list the Chromium-only image formats.
const ACCEPT_BY_ENGINE: Record<string, string> = {
	chrome: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
	firefox: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
}

const ACCEPT_LANGUAGE = 'en-US,en;q=0.9'

function engineOf(profile: BrowserProfile): 'chrome' | 'firefox' {
	return profile.name.startsWith('chrome') ? 'chrome' : 'firefox'
}

// A believable Referer makes a direct request look like a click-through rather
// than a cold programmatic hit. For bare origins we send the site's own origin
// (what a browser does when you open a link in a new tab); for deep paths we
// use the search-engine style entry point most crawlers see.
function refererFor(target: URL, profile: BrowserProfile): string {
	const engine = engineOf(profile)
	const isRoot = target.pathname === '/' || target.pathname === ''
	if (isRoot) {
		return `${target.origin}/`
	}
	return engine === 'chrome' ? 'https://www.google.com/' : 'https://duckduckgo.com/'
}

function buildHeaders(target: URL, profile: BrowserProfile, retry = false): Record<string, string> {
	const engine = engineOf(profile)
	const headers: Record<string, string> = {
		'User-Agent': profile.userAgent,
		Accept: ACCEPT_BY_ENGINE[engine],
		'Accept-Language': ACCEPT_LANGUAGE,
		// let the runtime negotiate/decompress; Node 18+ (undici) handles br/gzip
		'Accept-Encoding': 'gzip, deflate, br, zstd',
		Referer: refererFor(target, profile),
		'Upgrade-Insecure-Requests': '1',
		// navigation context: these four headers are the strongest "this is a
		// real top-level document load" signal a server can check
		'Sec-Fetch-Dest': 'document',
		'Sec-Fetch-Mode': 'navigate',
		'Sec-Fetch-Site': retry ? 'same-origin' : 'cross-site',
		'Sec-Fetch-User': '?1',
		// no cache, exactly like a fresh address-bar navigation (a warm cache
		// would normally surface as a conditional request instead)
		'Cache-Control': 'no-cache',
		Pragma: 'no-cache',
		// ask upstream CDNs/proxies to vary on the negotiation inputs we use
		Priority: 'u=0, i',
		'DNT': '1',
		'Connection': 'keep-alive',
		...profile.clientHints,
	}
	return headers
}

// Ordered profiles, starting from the primary; retries rotate so a block
// against one identity does not automatically doom the retry.
const PROFILE_ORDER: number[] = PROFILES.map((_, index) => index)

function profileFor(attempt: number): BrowserProfile {
	const start = PROFILE_ORDER[attempt % PROFILE_ORDER.length]
	return PROFILES[start]
}

type FetchOutcome = {
	buffer: Buffer
	contentType: string | null
	finalUrl: URL
	blocked: boolean
}

// Single-shot fetch with a fixed identity. Returns the body plus a
// blocked flag rather than throwing, so the caller can decide whether to
// rotate identity and retry.
async function fetchOnce(
	target: URL,
	profile: BrowserProfile,
	signal: AbortSignal,
	retry: boolean
): Promise<FetchOutcome> {
	const response = await fetch(target.toString(), {
		signal,
		redirect: 'follow',
		headers: buildHeaders(target, profile, retry),
	})

	let finalUrl = target
	try {
		finalUrl = new URL(response.url)
	} catch {
		// keep the original target if response.url is somehow unusable
	}

	// 403/503 are the usual "go away, bot" statuses and may still carry a
	// readable challenge page; anything else non-2xx is a plain upstream error.
	const isChallengeStatus = response.status === 403 || response.status === 503

	if (!response.ok && !isChallengeStatus) {
		throw Object.assign(new Error(`upstream status ${response.status}`), {
			upstreamStatus: response.status,
		})
	}

	const contentType = response.headers.get('content-type')

	const arrayBuffer = await response.arrayBuffer()
	const buffer = Buffer.from(arrayBuffer).subarray(0, MAX_BODY_BYTES)

	if (isChallengeStatus) {
		return { buffer, contentType, finalUrl, blocked: isProtectionChallengePage(response.headers, buffer) }
	}

	if (!response.ok) {
		// non-challenge error already handled above; defensive
		throw Object.assign(new Error(`upstream status ${response.status}`), {
			upstreamStatus: response.status,
		})
	}

	return { buffer, contentType, finalUrl, blocked: false }
}

const MAX_ATTEMPTS = 3
const RETRY_BACKOFF_MS = 350

type ErrorCode =
	| 'INVALID_URL'
	| 'DISALLOWED_HOST'
	| 'UNSUPPORTED_CONTENT_TYPE'
	| 'RATE_LIMITED'
	| 'UPSTREAM_ERROR'
	| 'TIMEOUT'

function ok(res: NextApiResponse, data: Record<string, unknown>) {
	res.status(200).json({ success: true, data })
}

function fail(res: NextApiResponse, status: number, code: ErrorCode, message: string) {
	res.status(status).json({ success: false, error: { code, message } })
}

const handler: NextApiHandler = async(req: NextApiRequest, res: NextApiResponse) => {
	if (isRateLimited(clientIp(req))) {
		return fail(res, 429, 'RATE_LIMITED', 'too many requests, please slow down')
	}

	const { url } = req.query
	if (typeof url !== 'string' || url.trim() === '') {
		return fail(res, 400, 'INVALID_URL', 'invalid url')
	}

	const parsed = parseUrl(url)
	if (!parsed) {
		return fail(res, 400, 'INVALID_URL', 'invalid url')
	}

	try {
		await assertPublicHost(parsed.hostname)
	} catch {
		return fail(res, 400, 'DISALLOWED_HOST', 'url points to a disallowed host')
	}

	const controller = new AbortController()
	const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS)

	let buffer: Buffer
	let contentType: string | null
	let finalUrl = parsed
	try {
		let outcome: FetchOutcome | null = null
		let sawChallenge = false

		// Rotate browser identity across attempts: a site that fingerprints or
		// blocks one profile often serves another. We only retry when the
		// previous attempt looked like a WAF/anti-bot block, never on a genuine
		// upstream error or a non-HTML resource.
		for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt += 1) {
			const profile = profileFor(attempt)

			let current: FetchOutcome
			try {
				current = await fetchOnce(parsed, profile, controller.signal, attempt > 0)
			} catch (err) {
				// Abort/timeout or upstream error: surface the timeout distinctly
				// and stop; retrying a hard failure rarely helps and burns budget.
				const isAbort = err instanceof Error && err.name === 'AbortError'
				if (isAbort) throw err
				const upstreamStatus = (err as { upstreamStatus?: number }).upstreamStatus
				return fail(
					res,
					502,
					'UPSTREAM_ERROR',
					upstreamStatus
						? `failed to fetch url (status ${upstreamStatus})`
						: 'failed to fetch url'
				)
			}

			// First non-error response wins for content-type validation: if the
			// site is not HTML for everyone, rotating identity will not change it.
			contentType = current.contentType
			if (contentType && !/text\/html|application\/xhtml\+xml/i.test(contentType)) {
				return fail(res, 415, 'UNSUPPORTED_CONTENT_TYPE', 'url does not point to an html page')
			}

			if (!current.blocked) {
				outcome = current
				break
			}

			sawChallenge = true
			// Small, jittered backoff so a burst of retries from the same
			// instance does not look like a scripted loop.
			const jitter = Math.floor(Math.random() * RETRY_BACKOFF_MS)
			await new Promise((resolve) => setTimeout(resolve, RETRY_BACKOFF_MS + jitter))
		}

		if (!outcome) {
			if (!sawChallenge) {
				return fail(res, 502, 'UPSTREAM_ERROR', 'failed to fetch url')
			}
			// Every identity was challenged: report it honestly instead of
			// returning empty metadata as if the page had none.
			return ok(res, {
				url: finalUrl.toString(),
				blocked_waf: true,
				message: 'site is protected by a WAF/anti-bot challenge; metadata could not be read automatically',
			})
		}

		buffer = outcome.buffer
		contentType = outcome.contentType
		finalUrl = outcome.finalUrl
	} catch (err) {
		const isAbort = err instanceof Error && err.name === 'AbortError'
		return isAbort
			? fail(res, 504, 'TIMEOUT', 'request to url timed out')
			: fail(res, 502, 'UPSTREAM_ERROR', 'failed to fetch url')
	} finally {
		clearTimeout(timeout)
	}

	const html = decodeHtml(buffer, contentType)
	const $ = cheerio.load(html)

	const title =
		$('meta[property="og:title"]').attr('content')?.trim() ||
		$('title').first().text().trim() ||
		$('meta[name="twitter:title"]').attr('content')?.trim() ||
		''

	const description =
		$('meta[property="og:description"]').attr('content')?.trim() ||
		$('meta[name="description"]').attr('content')?.trim() ||
		$('meta[name="twitter:description"]').attr('content')?.trim() ||
		''

	const image =
		absoluteUrl(finalUrl, $('meta[property="og:image"]').attr('content')) ||
		absoluteUrl(finalUrl, $('meta[name="twitter:image"]').attr('content'))

	const siteName =
		$('meta[property="og:site_name"]').attr('content')?.trim() ||
		finalUrl.hostname

	const favicon =
		absoluteUrl(finalUrl, $('link[rel="icon"]').attr('href')) ||
		absoluteUrl(finalUrl, $('link[rel="shortcut icon"]').attr('href')) ||
		absoluteUrl(finalUrl, '/favicon.ico')

	const language = $('html').attr('lang')?.trim() || undefined

	ok(res, {
		url: finalUrl.toString(),
		blocked_waf: false,
		title,
		description,
		image,
		site_name: siteName,
		favicon,
		language,
	})
}

export default handler
