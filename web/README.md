# mail-auth playground

A static, browser-only demo of [mail-auth](https://github.com/stalwartlabs/mail-auth):
DKIM, DKIM2 and DMARC compiled to WebAssembly. All signing happens client-side;
no message or key ever leaves the page.

This is a standalone crate (its own workspace) that depends on the parent
`mail-auth` crate via path. It is never published.

## Layout

- `src/lib.rs`: `wasm-bindgen` exports over the mail-auth API.
- `site/`: static `index.html`, `style.css` and JS glue. The build copies the
  generated `pkg/` next to these files.
- `build.sh`: runs `wasm-pack` and assembles `dist/`.

## Build

```sh
cargo install wasm-pack   # once
./web/build.sh            # outputs web/dist/
python3 -m http.server --directory web/dist 8080
```

Then open http://localhost:8080.

## Crate features

The WASM build uses mail-auth's WebAssembly-compatible features:
`rust-crypto` (pure-Rust crypto) and `dns-doh` (DNS-over-HTTPS, which also
provides the `web-time` browser clock). The default `aws-lc-rs` and
`dns-hickory` features are not WASM-compatible and are disabled.

## Deploy

Pushes to `main` that touch `web/`, `src/` or `Cargo.toml` trigger
`.github/workflows/pages.yml`, which builds the site and publishes it to GitHub
Pages. The `dist/` folder is a plain static bundle, so it can also be pointed at
Cloudflare Pages (build command `./web/build.sh`, output directory `web/dist`).
