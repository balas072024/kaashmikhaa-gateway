# Kaashmikhaa Technologies — Project Context

## Owner
Bala (Balamurugan Suriyaprakash) — Abu Dhabi, UAE
Application Support Manager at Etihad Airways

## Domain
arivumaiyam.com via Cloudflare tunnel → Flask gateway on port 5013

## All Apps & Ports
| App | Port | Stack |
|---|---|---|
| kaashmikhaa-gateway | 5013 | Python Flask |
| clawarivu | 18789 | Node.js |
| neural-brain-api | 8200 | Python FastAPI |
| opsshiftpro | 4000 | Node.js |
| opswatch-unified | 3001 | Node.js |
| valluvan-astrologer | 5000 | Python Flask |
| vault-browser | 4100 | Node.js |
| arivuwatch | 9000 | Node.js |
| family-hub | via gateway | HTML |

## Credentials
- Private sites password: arivu2026
- OpsShiftPro: bala@etihad.ae / opsshift2026
- OpsWatch: admin / opswatch2026
- Valluvan: admin@valluvan.app / admin123
- Family Hub: bala / arivu2024bala

## AI Providers
- Primary: MiniMax-M2.5 (https://api.minimax.io/anthropic/v1/messages, x-api-key)
- Vision: MiniMax-VL-01 same endpoint, max_tokens 4096
- Fallback: OpenRouter, Neural Brain (localhost:8200), Ollama (localhost:11434)

## Key Paths
- ClawArivu: C:\Users\LENOVO\.openclaw\workspace\clawarivu\
- Neural Brain: C:\Antigravity\neural-brain-api\
- All products: C:\Antigravity\

## Instructions for Claude Code
- Always read this file first before making changes
- Use UTF-8 encoding for all Python files
- Node.js apps use better-sqlite3 for database
- All APIs need CORS headers for cross-origin requests
- Telegram bot token: 8248409638:AAGfoRar3Ln8dStiw9BEzlCJQwf6YT9LD78
- MiniMax API key in .env as MINIMAX_API_KEY