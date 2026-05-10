/**
 * ═══════════════════════════════════════════════════════════════════════════
 * Telegram-Backed Image Hosting — Cloudflare Worker
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * A single self-contained worker. Copy-paste into Cloudflare Workers dashboard
 * or use with wrangler (set main = "worker.js" in wrangler.toml).
 *
 * Required Secrets (set in CF dashboard or via `wrangler secret put`):
 *   BOT_TOKEN     — Telegram bot token
 *   BOT_CHANNEL   — Private channel ID (-100XXXXXXXXXX)
 *   SIA_SECRET    — Long random string for encryption
 *   CF_WORKER_KEY — Shared auth key with Vercel
 *
 * Endpoints:
 *   POST /upload           — Upload image (auth required via X-Worker-Key)
 *   GET  /retrieve?file=X  — Stream image (public, encryption = access control)
 *   GET  /health           — Health check
 */

// ─────────────────────────────────────────────────────────────────────────────
// Cryptic — XOR + Base32 Encryption
// ─────────────────────────────────────────────────────────────────────────────

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

class Cryptic {
  static getSalt(length = 16) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const randomBytes = new Uint8Array(length);
    crypto.getRandomValues(randomBytes);
    let salt = '';
    for (let i = 0; i < length; i++) {
      salt += chars[randomBytes[i] % chars.length];
    }
    return salt;
  }

  static getKey(salt, secret, iterations = 1000, keyLength = 32) {
    const key = new Array(keyLength);
    for (let i = 0; i < keyLength; i++) {
      key[i] = (secret.charCodeAt(i % secret.length) + salt.charCodeAt(i % salt.length)) % 256;
    }
    for (let round = 0; round < iterations; round++) {
      for (let i = 0; i < keyLength; i++) {
        key[i] = (key[i] ^ secret.charCodeAt((round + i) % secret.length) ^ salt.charCodeAt((round + i) % salt.length)) % 256;
      }
    }
    return key;
  }

  static baseEncode(input) {
    let bits = '';
    for (let i = 0; i < input.length; i++) {
      bits += input[i].toString(2).padStart(8, '0');
    }
    while (bits.length % 5 !== 0) bits += '0';
    let encoded = '';
    for (let i = 0; i < bits.length; i += 5) {
      encoded += BASE32_ALPHABET[parseInt(bits.substring(i, i + 5), 2)];
    }
    return encoded;
  }

  static baseDecode(input) {
    let bits = '';
    for (let i = 0; i < input.length; i++) {
      const idx = BASE32_ALPHABET.indexOf(input[i]);
      if (idx === -1) throw new Error(`Invalid Base32 character: ${input[i]}`);
      bits += idx.toString(2).padStart(5, '0');
    }
    const bytes = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) {
      bytes.push(parseInt(bits.substring(i, i + 8), 2));
    }
    return new Uint8Array(bytes);
  }

  static Hash(text, secret) {
    const salt = Cryptic.getSalt(16);
    const key = Cryptic.getKey(salt, secret);
    const xored = [];
    for (let i = 0; i < text.length; i++) {
      xored.push(text.charCodeAt(i) ^ key[i % key.length]);
    }
    const saltBytes = [];
    for (let i = 0; i < salt.length; i++) {
      saltBytes.push(salt.charCodeAt(i));
    }
    const combined = new Uint8Array([...saltBytes, ...xored]);
    return Cryptic.baseEncode(combined);
  }

  static deHash(hashed, secret) {
    let decoded;
    try {
      decoded = Cryptic.baseDecode(hashed);
    } catch (e) {
      throw new Error('Invalid encrypted code: malformed Base32');
    }
    if (decoded.length < 17) {
      throw new Error('Invalid encrypted code: too short');
    }
    const saltBytes = decoded.slice(0, 16);
    const xoredBytes = decoded.slice(16);
    let salt = '';
    for (let i = 0; i < saltBytes.length; i++) {
      salt += String.fromCharCode(saltBytes[i]);
    }
    const key = Cryptic.getKey(salt, secret);
    let original = '';
    for (let i = 0; i < xoredBytes.length; i++) {
      original += String.fromCharCode(xoredBytes[i] ^ key[i % key.length]);
    }
    return original;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Rate Limiting (in-memory, resets on worker restart)
// ─────────────────────────────────────────────────────────────────────────────

const rateLimitMap = new Map();
const RATE_LIMIT_MAX = 20;
const RATE_LIMIT_WINDOW = 60 * 60 * 1000; // 1 hour

function checkRateLimit(ip) {
  const now = Date.now();
  const entry = rateLimitMap.get(ip);
  if (!entry || now > entry.resetTime) {
    rateLimitMap.set(ip, { count: 1, resetTime: now + RATE_LIMIT_WINDOW });
    return true;
  }
  if (entry.count >= RATE_LIMIT_MAX) return false;
  entry.count++;
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Response Helpers
// ─────────────────────────────────────────────────────────────────────────────

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Worker-Key',
};

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
  });
}

function errorResponse(error, status = 500) {
  return jsonResponse({ ok: false, error }, status);
}

// ─────────────────────────────────────────────────────────────────────────────
// Telegram API Helpers
// ─────────────────────────────────────────────────────────────────────────────

async function telegramAPI(env, method, body, isMultipart = false) {
  const url = `https://api.telegram.org/bot${env.BOT_TOKEN}/${method}`;
  const options = { method: 'POST' };
  if (isMultipart) {
    options.body = body;
  } else {
    options.headers = { 'Content-Type': 'application/json' };
    options.body = JSON.stringify(body);
  }
  const res = await fetch(url, options);
  return res.json();
}

function extractFileId(message) {
  if (message.photo && message.photo.length > 0) {
    return message.photo[message.photo.length - 1].file_id;
  }
  if (message.document) return message.document.file_id;
  if (message.video) return message.video.file_id;
  if (message.animation) return message.animation.file_id;
  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Stream file bytes from Telegram to the client
// ─────────────────────────────────────────────────────────────────────────────

async function streamFile(env, fileId) {
  const fileInfo = await telegramAPI(env, 'getFile', { file_id: fileId });
  if (!fileInfo.ok) {
    return errorResponse(`Telegram getFile error: ${fileInfo.description || 'Unknown'}`, 422);
  }

  const filePath = fileInfo.result.file_path;
  const fileURL = `https://api.telegram.org/file/bot${env.BOT_TOKEN}/${filePath}`;
  const fileResponse = await fetch(fileURL);

  if (!fileResponse.ok) {
    return errorResponse('Failed to fetch file from Telegram servers', 502);
  }

  const ext = filePath.split('.').pop()?.toLowerCase();
  const mimeMap = {
    jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png',
    gif: 'image/gif', webp: 'image/webp', svg: 'image/svg+xml',
    mp4: 'video/mp4', pdf: 'application/pdf',
  };
  const contentType = mimeMap[ext] || 'application/octet-stream';
  const fileName = filePath.split('/').pop() || 'file';

  return new Response(fileResponse.body, {
    status: 200,
    headers: {
      ...CORS_HEADERS,
      'Content-Type': contentType,
      'Content-Disposition': `inline; filename="${fileName}"`,
      'Cache-Control': 'public, max-age=31536000, immutable',
    },
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /upload
// ─────────────────────────────────────────────────────────────────────────────

async function handleUpload(request, env) {
  // Auth
  const workerKey = request.headers.get('X-Worker-Key');
  if (!workerKey || workerKey !== env.CF_WORKER_KEY) {
    return errorResponse('Unauthorized: invalid or missing X-Worker-Key', 403);
  }

  // Rate limit
  const clientIP = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'unknown';
  if (!checkRateLimit(clientIP)) {
    return errorResponse('Rate limit exceeded. Maximum 20 uploads per hour.', 429);
  }

  try {
    const formData = await request.formData();
    const file = formData.get('file');
    const mimeType = formData.get('mime_type') || 'image/jpeg';

    if (!file) return errorResponse('Missing file in request body', 400);
    if (!mimeType.startsWith('image/')) return errorResponse('Only image files are accepted', 415);

    // Pick sendPhoto vs sendDocument
    const fileSize = file.size || 0;
    const usePhoto = mimeType.startsWith('image/') && fileSize < 10 * 1024 * 1024 && !mimeType.includes('svg');
    const method = usePhoto ? 'sendPhoto' : 'sendDocument';

    const tgForm = new FormData();
    tgForm.append('chat_id', env.BOT_CHANNEL);
    tgForm.append(usePhoto ? 'photo' : 'document', file, usePhoto ? 'image.jpg' : 'file');

    const tgResponse = await telegramAPI(env, method, tgForm, true);
    if (!tgResponse.ok) {
      return errorResponse(`Telegram error: ${tgResponse.description || 'Unknown error'}`, 422);
    }

    const messageId = tgResponse.result.message_id;
    const encryptedCode = Cryptic.Hash(String(messageId), env.SIA_SECRET);

    return jsonResponse({ ok: true, encrypted_code: encryptedCode, message_id: messageId });
  } catch (err) {
    return errorResponse(`Upload failed: ${err.message}`, 500);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /retrieve?file={encrypted_code}
// ─────────────────────────────────────────────────────────────────────────────

async function handleRetrieve(request, env) {
  const url = new URL(request.url);
  const encryptedCode = url.searchParams.get('file');
  if (!encryptedCode) return errorResponse('Missing "file" query parameter', 400);

  try {
    // Decrypt
    let messageId;
    try {
      messageId = Cryptic.deHash(encryptedCode, env.SIA_SECRET);
    } catch (e) {
      return errorResponse('Invalid file code', 400);
    }

    const numericMessageId = parseInt(messageId, 10);
    if (isNaN(numericMessageId)) return errorResponse('Invalid file code: corrupted data', 400);

    // Try editMessageCaption to get fresh file_id
    const captionUUID = crypto.randomUUID();
    const editResult = await telegramAPI(env, 'editMessageCaption', {
      chat_id: env.BOT_CHANNEL,
      message_id: numericMessageId,
      caption: captionUUID,
    });

    if (editResult.ok) {
      const fileId = extractFileId(editResult.result);
      if (fileId) return await streamFile(env, fileId);
    }

    // Fallback: forwardMessage → extract file_id → delete forward
    const forwardResult = await telegramAPI(env, 'forwardMessage', {
      chat_id: env.BOT_CHANNEL,
      from_chat_id: env.BOT_CHANNEL,
      message_id: numericMessageId,
    });

    if (!forwardResult.ok) {
      return errorResponse(`Telegram error: ${forwardResult.description || 'Cannot retrieve file'}`, 422);
    }

    const fileId = extractFileId(forwardResult.result);
    if (!fileId) return errorResponse('Could not extract file from Telegram message', 422);

    // Clean up forwarded message (fire and forget)
    telegramAPI(env, 'deleteMessage', {
      chat_id: env.BOT_CHANNEL,
      message_id: forwardResult.result.message_id,
    }).catch(() => {});

    return await streamFile(env, fileId);
  } catch (err) {
    return errorResponse(`Retrieve failed: ${err.message}`, 500);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /health
// ─────────────────────────────────────────────────────────────────────────────

function handleHealth() {
  return jsonResponse({ ok: true, timestamp: new Date().toISOString(), service: 'image-hosting-worker' });
}

// ─────────────────────────────────────────────────────────────────────────────
// Main Router
// ─────────────────────────────────────────────────────────────────────────────

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const { pathname } = url;
    const method = request.method;

    // CORS preflight
    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    if (method === 'POST' && pathname === '/upload') return handleUpload(request, env);
    if (method === 'GET' && pathname === '/retrieve') return handleRetrieve(request, env);
    if (method === 'GET' && pathname === '/health') return handleHealth();

    return errorResponse('Not found', 404);
  },
};
