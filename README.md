# QUIC

`quic` is a thin Ruby binding around [ngtcp2](https://github.com/ngtcp2/ngtcp2) for the QUIC transport protocol. TLS 1.3 is handled by [picotls](https://github.com/h2o/picotls), which uses the libcrypto of [LibreSSL](https://github.com/libressl/portable) for its cryptographic primitives and X.509 handling. All three dependencies are vendored at install time via [`mini_portile2`](https://github.com/flavorjones/mini_portile) (no system libraries required).

The gem is intentionally optimized for **synchronous I/O and `String`-based buffers**. It exposes ngtcp2 primitives (`#read_pkt` / `#write_pkt` / `#expiry` / `#handle_expiry`) and lets the caller own the I/O loop. If you need Fiber Scheduler / `IO::Buffer` / `async` ecosystem integration, see [`socketry/protocol-quic`](https://github.com/socketry/protocol-quic) instead.

This project is in early development; the public API is not yet stable.

## Installation

```ruby
gem "quic"
```

On `x86_64-linux-gnu` with Ruby 3.4 or 4.0, a precompiled gem is installed. It bundles `quic.so` with LibreSSL, picotls and ngtcp2 statically linked, so no build tools are required.

Everywhere else — musl-based distributions, other architectures, other Ruby versions — the source gem is installed instead. It downloads and builds LibreSSL, picotls and ngtcp2 during installation, so the host needs `autoconf`, `automake`, `libtool`, `pkg-config`, a C toolchain, and either `patch` or `git` (picotls is patched before it is built; `mini_portile2` uses `git apply` when `git` is available and falls back to `patch -p1`).

## Limitations

- **Server certificates are not verified.** Neither the certificate chain nor the CertificateVerify signature against the leaf public key is checked, so there is no protection against an active attacker. Verification is planned but not implemented.
- **No session resumption or 0-RTT.**
- **No server side.** Only the client (`QUIC::Connection::Client`) exists; there is no listen/accept.
- **Key exchanges and cipher suites are fixed.** X25519, secp256r1 and secp384r1 with AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305. They cannot be selected from Ruby.

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then run `bundle exec rake` to compile the C extension and run the tests + linter. You can also run `bin/console` for an interactive prompt.

To install this gem onto your local machine, run `bundle exec rake install`.

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/unasuke/quic-ruby. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [code of conduct](https://github.com/unasuke/quic-ruby/blob/main/CODE_OF_CONDUCT.md).

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

The precompiled `x86_64-linux-gnu` gem statically links [LibreSSL](https://www.libressl.org/) (OpenSSL/SSLeay and ISC licenses), [picotls](https://github.com/h2o/picotls) (MIT, with one file under an ISC-style license) and [ngtcp2](https://github.com/ngtcp2/ngtcp2) (MIT, with portions under the Chromium BSD-3-Clause license). Their license texts are in [LICENSE-DEPENDENCIES.txt](LICENSE-DEPENDENCIES.txt).

This product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit (http://www.openssl.org/). This product includes cryptographic software written by Eric Young (eay@cryptsoft.com).

## Code of Conduct

Everyone interacting in the quic-ruby project's codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/unasuke/quic-ruby/blob/main/CODE_OF_CONDUCT.md).
