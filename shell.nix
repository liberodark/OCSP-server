{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    rustc
    cargo
    cargo-audit
    clippy
    rustfmt
    rust-analyzer
    git
    openssl
    libmysqlclient
    sqlite
    postgresql
    pkg-config
  ];

  shellHook = ''
    rustfmt --edition 2021 src/*.rs
    cargo audit
    export CARGO_NET_GIT_FETCH_WITH_CLI=true
  '';

  RUST_BACKTRACE = 1;
}
