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

function absoluteUrl(base: URL, maybeRelative: string | undefined): string | undefined {
	if (!maybeRelative) return undefined
	try {
		return new URL(maybeRelative, base).toString()
	} catch {
		return undefined
	}
}

const handler: NextApiHandler = async(req: NextApiRequest, res: NextApiResponse) => {
	if (isRateLimited(clientIp(req))) {
		return res.status(429).json({
			msg: 'too many requests, please slow down'
		})
	}

	const { url } = req.query
	if (typeof url !== 'string' || url.trim() === '') {
		return res.status(400).json({
			msg: 'invalid url'
		})
	}

	const parsed = parseUrl(url)
	if (!parsed) {
		return res.status(400).json({
			msg: 'invalid url'
		})
	}

	try {
		await assertPublicHost(parsed.hostname)
	} catch {
		return res.status(400).json({
			msg: 'url points to a disallowed host'
		})
	}

	const controller = new AbortController()
	const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS)

	let buffer: Buffer
	let contentType: string | null
	try {
		const response = await fetch(parsed.toString(), {
			signal: controller.signal,
			redirect: 'follow',
			headers: {
				'User-Agent': 'Mozilla/5.0 (compatible; metafetch-bot/1.0; +https://metafetch.vercel.app)',
				'Accept': 'text/html,application/xhtml+xml',
			},
		})

		if (!response.ok) {
			return res.status(502).json({
				msg: `failed to fetch url (status ${response.status})`
			})
		}

		contentType = response.headers.get('content-type')
		if (contentType && !/text\/html|application\/xhtml\+xml/i.test(contentType)) {
			return res.status(415).json({
				msg: 'url does not point to an html page'
			})
		}

		const arrayBuffer = await response.arrayBuffer()
		buffer = Buffer.from(arrayBuffer).subarray(0, MAX_BODY_BYTES)
	} catch (err) {
		const isAbort = err instanceof Error && err.name === 'AbortError'
		return res.status(isAbort ? 504 : 502).json({
			msg: isAbort ? 'request to url timed out' : 'failed to fetch url'
		})
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
		absoluteUrl(parsed, $('meta[property="og:image"]').attr('content')) ||
		absoluteUrl(parsed, $('meta[name="twitter:image"]').attr('content'))

	const siteName =
		$('meta[property="og:site_name"]').attr('content')?.trim() ||
		parsed.hostname

	const favicon =
		absoluteUrl(parsed, $('link[rel="icon"]').attr('href')) ||
		absoluteUrl(parsed, $('link[rel="shortcut icon"]').attr('href')) ||
		absoluteUrl(parsed, '/favicon.ico')

	const language = $('html').attr('lang')?.trim() || undefined

	res.status(200).json({
		url: parsed.toString(),
		title,
		description,
		image,
		siteName,
		favicon,
		language,
	})
}

export default handler
