# kryoto-messaging

The end-to-end encryption behind Kryoto chat, in one Rust workspace. The
desktop app links it natively; the web client runs the same code as
WebAssembly. No cryptography is written anywhere else.

| Crate | What it is |
|---|---|
| `km-proto` | Wire formats (protobuf via `prost`, no `protoc`) |
| `km-core` | Master key + device cross-signing, Olm sessions (Double Ratchet), sealed envelopes, trust pinning and key-change detection, safety numbers. No I/O |
| `km-store-sqlcipher` | The desktop's encrypted database for that state |
| `km-wasm` | The web client's binding (`wasm-bindgen`): one `Kryo` object holding the account state, gateway frames, encrypt/decrypt, verification, key backup, attachment sealing |

## Building blocks

Nothing here is home-made cryptography. Every primitive comes from a
maintained, reviewed library:

- **Olm / Double Ratchet** (1:1 sessions, forward secrecy, post-compromise
  security): [vodozemac](https://github.com/matrix-org/vodozemac), audited by
  Least Authority.
- **Sealed outer layer** (keeps the sender out of server storage): RFC 9180
  HPKE, base mode, X25519 / HKDF-SHA256 / ChaCha20-Poly1305, via the `hpke`
  crate (the same suite vodozemac uses).
- **Signatures**: Ed25519.
- **Safety numbers**: Signal's numeric fingerprint construction (iterated
  SHA-512), computed over each user's master key.
- **Key backup and attachments**: XChaCha20-Poly1305 (`chacha20poly1305`).
  The backup key is a 240-bit recovery code; the backup is bound to the
  account it belongs to.
- **At rest (desktop)**: SQLCipher.

How these fit together: `FRIENDS-AND-CHAT.md` in the Kryoto workspace.

## Test

```text
cargo test --workspace                                   # native, incl. property tests
cargo test -p km-core --target wasm32-unknown-unknown --test wasm   # inside WebAssembly (Node)
```

Build the web client's module (used by `kryoto-desktop`'s `pnpm web:wasm`):

```text
cargo build -p km-wasm --target wasm32-unknown-unknown --release
wasm-bindgen --target web --out-dir <dir> target/wasm32-unknown-unknown/release/km_wasm.wasm
```

The WebAssembly tests and build need `rustup target add wasm32-unknown-unknown` and
`cargo install wasm-bindgen-cli --version <the version in Cargo.lock>`.

The SQLCipher store compiles OpenSSL from source, which needs a full Perl
(Strawberry Perl on Windows). On a machine without one:

```text
cargo test -p km-store-sqlcipher --no-default-features --features plain-sqlite-dev
```

That fallback is **not encrypted** and refuses to compile in release mode.

## Reporting a security problem

Please do not open a public issue. Email hello@kryo.to with "security" in the subject.

## License

MIT. See `LICENSE`.
