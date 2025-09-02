# JWT Editor (In‑Browser)

A lightweight, client‑only JWT editor you can host on GitHub Pages. Decode, edit, verify, and (re)sign JSON Web Tokens using the Web Crypto API — no servers, no tracking.

## Features

- HS256 / HS384 / HS512 sign and verify (HMAC)
- Live decode of header and payload (Base64URL)
- JSON editors with pretty‑print helpers
- Visual signature verification status
- Humanized standard claims: `iat`, `nbf`, `exp`
- Optional Base64URL secret input
- Copy token, keep state in `localStorage`

Note: `alg: "none"` is supported for assembling unsigned tokens (with a clear warning). Asymmetric algorithms like RS256 are not included to keep the app dependency‑free and simple.

## Run locally

Simply open `index.html` in a modern browser (no build step needed).

## Deploy to GitHub Pages

1. Create a new GitHub repository (or use an existing one).
2. Add these files to the root of the repository and push.
3. In the repo settings, enable GitHub Pages:
   - Settings → Pages → Build and deployment
   - Source: Deploy from a branch
   - Branch: `main` (or `master`), folder `/ (root)`
4. Wait for the page to build, then visit the provided `https://<your-username>.github.io/<repo>/` URL.

Alternatively, place the site under a `docs/` folder and set Pages to serve from `docs`.

## Security notes

- All crypto and parsing runs locally in your browser — tokens and secrets never leave the page.
- Be careful when sharing links; the app supports `?token=...` or `#token=...` in the URL for convenience, but it never stores or embeds secrets in links.
- Verify results only cover HMAC algorithms (HS*). For RS*/ES* tokens you can still decode, but verification is not implemented.

## License

This project is provided as‑is with no warranty. Use at your own risk.
