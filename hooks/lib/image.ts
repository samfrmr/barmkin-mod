import { REDACTION_RULES } from './redaction-rules'
import { containsAnySecret, exceedsScanLimit } from './redaction'

export type ImageVerdict = { ok: true } | { ok: false; reason: string }

const NOT_IMAGE = 'this Read returned an image payload that is not a recognised image format'
const UNSCANNABLE =
  'this Read returned an image whose metadata cannot be scanned (a block over the 16 KiB scan limit or an unsupported compression method)'
const SECRET = 'this Read returned an image whose metadata contains a secret-shaped value'

type MetadataBlock = { data: string; inflate: boolean } | { unscannable: true }

const UNSCANNABLE_BLOCK: MetadataBlock = { unscannable: true }

const u8 = (b: string, i: number) => b.charCodeAt(i)
const u16be = (b: string, i: number) => u8(b, i) * 256 + u8(b, i + 1)
const u32be = (b: string, i: number) => u8(b, i) * 16777216 + u8(b, i + 1) * 65536 + u8(b, i + 2) * 256 + u8(b, i + 3)
const u32le = (b: string, i: number) => u8(b, i) + u8(b, i + 1) * 256 + u8(b, i + 2) * 65536 + u8(b, i + 3) * 16777216

function pngTextBlocks(type: string, body: string): MetadataBlock[] {
  const blocks: MetadataBlock[] = [{ data: body, inflate: false }]
  if (type !== 'zTXt' && type !== 'iTXt') return blocks
  const keywordEnd = body.indexOf('\0')
  if (keywordEnd < 0) return [UNSCANNABLE_BLOCK]
  if (type === 'zTXt') {
    if (u8(body, keywordEnd + 1) !== 0) return [UNSCANNABLE_BLOCK]
    blocks.push({ data: body.slice(keywordEnd + 2), inflate: true })
  } else if (u8(body, keywordEnd + 1) === 1) {
    if (u8(body, keywordEnd + 2) !== 0) return [UNSCANNABLE_BLOCK]
    const languageEnd = body.indexOf('\0', keywordEnd + 3)
    const translatedEnd = languageEnd < 0 ? -1 : body.indexOf('\0', languageEnd + 1)
    if (translatedEnd < 0) return [UNSCANNABLE_BLOCK]
    blocks.push({ data: body.slice(translatedEnd + 1), inflate: true })
  }
  return blocks
}

function pngMetadata(b: string): MetadataBlock[] | null {
  const blocks: MetadataBlock[] = []
  let pos = 8
  for (let first = true; pos + 8 <= b.length; first = false) {
    const len = u32be(b, pos)
    const type = b.slice(pos + 4, pos + 8)
    if (first && (type !== 'IHDR' || len !== 13)) return null
    const start = pos + 8
    pos += 12 + len
    if (pos > b.length) return null
    if (type === 'IEND') return pos === b.length ? blocks : null
    if (u8(type, 0) & 0x20) blocks.push(...pngTextBlocks(type, b.slice(start, start + len)))
  }
  return null
}

function jpegMetadata(b: string): MetadataBlock[] | null {
  const blocks: MetadataBlock[] = []
  let pos = 2
  while (pos + 4 <= b.length) {
    if (u8(b, pos) !== 0xff) return null
    const marker = u8(b, pos + 1)
    if (marker === 0xff) {
      pos += 1
    } else if (marker === 0xd8 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) {
      pos += 2
    } else if (marker === 0xd9) {
      return null
    } else {
      const len = u16be(b, pos + 2)
      if (len < 2 || pos + 2 + len > b.length) return null
      if (marker >= 0xc0 && marker <= 0xcf && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc) {
        return len >= 8 ? blocks : null
      }
      if ((marker >= 0xe0 && marker <= 0xef) || marker === 0xfe) {
        blocks.push({ data: b.slice(pos + 4, pos + 2 + len), inflate: false })
      }
      pos += 2 + len
    }
  }
  return null
}

function gifSubBlocks(b: string, pos: number): { end: number; data: string } | null {
  let data = ''
  while (pos < b.length) {
    const size = u8(b, pos)
    if (size === 0) return { end: pos + 1, data }
    data += b.slice(pos + 1, pos + 1 + size)
    pos += 1 + size
    if (pos > b.length) return null
  }
  return null
}

function gifMetadata(b: string): MetadataBlock[] | null {
  if (b.length < 13) return null
  let pos = 13
  const flags = u8(b, 10)
  if (flags & 0x80) pos += 3 * 2 ** ((flags & 7) + 1)
  const blocks: MetadataBlock[] = []
  while (pos < b.length) {
    const introducer = u8(b, pos)
    if (introducer === 0x3b) return pos + 1 === b.length ? blocks : null
    if (introducer === 0x21) {
      const sub = gifSubBlocks(b, pos + 2)
      if (!sub) return null
      blocks.push({ data: sub.data, inflate: false })
      pos = sub.end
    } else if (introducer === 0x2c) {
      if (pos + 10 > b.length) return null
      const imageFlags = u8(b, pos + 9)
      pos += 10
      if (imageFlags & 0x80) pos += 3 * 2 ** ((imageFlags & 7) + 1)
      const sub = gifSubBlocks(b, pos + 1)
      if (!sub) return null
      pos = sub.end
    } else {
      return null
    }
  }
  return null
}

function webpMetadata(b: string): MetadataBlock[] | null {
  if (b.length < 20 || b.slice(8, 12) !== 'WEBP' || u32le(b, 4) + 8 !== b.length) return null
  if (!['VP8 ', 'VP8L', 'VP8X'].includes(b.slice(12, 16))) return null
  const blocks: MetadataBlock[] = []
  let pos = 12
  while (pos + 8 <= b.length) {
    const type = b.slice(pos, pos + 4)
    const size = u32le(b, pos + 4)
    const end = pos + 8 + size + (size & 1)
    if (end > b.length) return null
    if (type !== 'VP8 ' && type !== 'VP8L') blocks.push({ data: b.slice(pos + 8, pos + 8 + size), inflate: false })
    pos = end
  }
  return pos === b.length ? blocks : null
}

async function inflateScannable(data: string): Promise<string | null> {
  try {
    const bytes = Uint8Array.from(data, (c) => c.charCodeAt(0))
    const reader = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate')).getReader()
    let text = ''
    for (;;) {
      const { done, value } = await reader.read()
      if (done) return text
      for (const byte of value) text += String.fromCharCode(byte)
      if (exceedsScanLimit(text)) {
        await reader.cancel()
        return null
      }
    }
  } catch {
    return null
  }
}

function metadataBlocks(bytes: string): MetadataBlock[] | null {
  if (bytes.startsWith('\x89PNG\r\n\x1a\n')) return pngMetadata(bytes)
  if (bytes.startsWith('\xff\xd8\xff')) return jpegMetadata(bytes)
  if (bytes.startsWith('GIF87a') || bytes.startsWith('GIF89a')) return gifMetadata(bytes)
  if (bytes.startsWith('RIFF')) return webpMetadata(bytes)
  return null
}

// Structural check of a Read image payload. The image data itself is never
// scanned: it reaches the transcript only as base64. Metadata blocks (PNG
// ancillary chunks, GIF extensions, JPEG APPn and COM segments, WebP
// non-bitstream chunks) are text the rules can match, so each is scanned, and
// zlib-compressed ones are inflated first. A block over the scan limit or
// with an unsupported compression method is withheld, and so is a block that
// holds a secret. Availability cost: an image with a corrupt structure, or
// metadata that cannot be scanned, is withheld rather than passed through.
export async function verifyImageBase64(payload: string): Promise<ImageVerdict> {
  let bytes: string
  try {
    bytes = atob(payload)
  } catch {
    return { ok: false, reason: NOT_IMAGE }
  }
  const blocks = metadataBlocks(bytes)
  if (!blocks) return { ok: false, reason: NOT_IMAGE }
  for (const block of blocks) {
    if ('unscannable' in block) return { ok: false, reason: UNSCANNABLE }
    const text = block.inflate ? await inflateScannable(block.data) : block.data
    if (text === null || exceedsScanLimit(text)) return { ok: false, reason: UNSCANNABLE }
    if (containsAnySecret(text, REDACTION_RULES)) return { ok: false, reason: SECRET }
  }
  return { ok: true }
}
