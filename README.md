# Image Hosting Worker — Cloudflare Backend

A Cloudflare Worker that serves as the backend for a Telegram-backed image hosting service. All image bytes flow through this worker — no files are ever stored on disk.

## Architecture

```
Browser ──► Vercel (Next.js) ──► This Worker ──► Telegram Bot API
Browser ◄── This Worker ◄───────────────────── Telegram File Server
```

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/upload` | `X-Worker-Key` header | Upload image to Telegram, returns encrypted code |
| `GET` | `/retrieve?file={code}` | None (encryption = access control) | Stream image from Telegram |
| `GET` | `/health` | None | Health check |

## Setup

### 1. Prerequisites
- [Node.js](https://nodejs.org/) 18+
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/) (`npm i -g wrangler`)
- A Cloudflare account
- A Telegram bot token (from [@BotFather](https://t.me/BotFather))
- A private Telegram channel (bot must be admin)

### 2. Install Dependencies
```bash
npm install
```

### 3. Configure Secrets
```bash
wrangler secret put BOT_TOKEN
# Paste your Telegram bot token

wrangler secret put BOT_CHANNEL
# Paste your private channel ID (e.g., -1001234567890)

wrangler secret put SIA_SECRET
# Paste a long random string (used for encryption)

wrangler secret put CF_WORKER_KEY
# Paste a shared secret (must match Vercel's CF_WORKER_KEY env var)
```

### 4. Local Development
Create a `.dev.vars` file from the example:
```bash
cp .dev.vars.example .dev.vars
# Edit .dev.vars with your actual values
```

Run locally:
```bash
npm run dev
```

### 5. Deploy
```bash
npm run deploy
```

## Security

- **Rate limiting**: 20 uploads/hour per IP (in-memory)
- **Auth**: `/upload` requires `X-Worker-Key` header
- **Encryption**: Message IDs are XOR + Base32 encrypted — cannot be enumerated without `SIA_SECRET`
- **CORS**: Configured for cross-origin access from the frontend

## Environment Variables

| Name | Description |
|------|-------------|
| `BOT_TOKEN` | Telegram bot token |
| `BOT_CHANNEL` | Private channel ID (-100XXXXXXXXXX) |
| `SIA_SECRET` | Encryption secret for XOR+Base32 |
| `CF_WORKER_KEY` | Shared auth key with Vercel frontend |
