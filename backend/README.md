# Darkie Tools — Website

The official landing page and live playground for the Darkie Tools repository.

## Run locally

```bash
./serve.sh              # serves on http://localhost:8000
PORT=9000 ./serve.sh    # custom port
```

Or manually:

```bash
# from the repository root
python -m http.server 8000 --directory website
```

Then open <http://localhost:8000/> in your browser.

## Design direction

The page is styled as a **neon night** — an anime cyber-night where the most
characteristic thing in a cyber toolkit's world is running a scan. A looping anime
video night sits behind the whole page (`bg.mp4`, dark neon cyber glow), and the
hero opens with a live, in-browser scan of the visitor's own public IP (via
`ipwho.is`, with `ipify` as fallback; no data is sent anywhere except to the
lookup API). A particle "connection map" and CRT scanlines overlay the video.

The direction deliberately avoids the templated "near-black + single acid accent"
look: the canvas is a deep violet-black with a **dual neon** of hot magenta and
electric cyan.

**Tokens** (see `styles.css`):

| Token | Hex | Role |
|-------|-----|------|
| `--void` | `#0b0614` | deep violet-black canvas |
| `--panel` | `#150d29` | indigo console surface |
| `--ink` | `#f4edff` | lavender ink |
| `--neon` | `#ff2f92` | hot magenta — the signature neon |
| `--cyber` | `#5ff0ff` | electric cyan — live data / success |
| `--volt` | `#ffd166` | amber — structure, warnings |

**Type:** display **Zen Tokyo Zoo** (anime brush, used with restraint — brand,
eyebrows, accent words), body **Space Grotesk**, data **JetBrains Mono**.

**Signature:** the anime video night + the terminal that live-scans the visitor's
own public IP, over a drifting particle connection map. Everything else stays
quiet and disciplined around it.

## Features

- Looping anime video background (`bg.mp4`) with graceful fallback to a particle map
- Live public-IP self-scan in the hero (types itself in, works offline via a fallback)
- Glitch typewriter headline, scroll-reveal module palette, animated stat counters
- Interactive 3D tilt on the hero console, ambient particle connection map
- Animated scrolling log tape with an audio-style wave in the console bar
- Live playground: GitHub queries (`latest-release`, `latest-commit`, `list-files`, `grep`) and client-side simulations (`simulate nmap`, `simulate osint`)
- Copy-to-clipboard install snippets for Linux/macOS/WSL and Windows
- Responsive, keyboard-focusable, respects `prefers-reduced-motion`

## Notes

- `bg.mp4` is a free-license anime "dark cyber glow" loop (Pixabay CC0, downloaded
  for self-hosting). Replace the file to swap the mood.
- GitHub API calls are unauthenticated and rate-limited (60 req/hr per IP).
- The IP lookup uses free public endpoints; no token is required.
- This is a static, read-only demo. Keep all operations legal: scan only systems you own or have permission to test.
