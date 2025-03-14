{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    rustc
    cargo
    cargo-audit
    rustfmt
    rust-analyzer
  ];

  shellHook = ''
    rustfmt --edition 2021 src/main.rs
    cargo audit
  '';

  RUST_BACKTRACE = 1;
}
