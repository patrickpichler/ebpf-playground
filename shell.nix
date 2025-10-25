{ pkgs ? import <nixpkgs> {} }:
let
  # Revision that contains libbpf 1.3.0
  pkgs_old = import(builtins.fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/8311011fcea909e0cc9684ada784dae080fbfb60.tar.gz";
  }) {};

  clang-format-18 = pkgs.writeShellScriptBin "clang-format-18" ''
    exec ${pkgs.clang-tools_18}/bin/clang-format "$@"
  '';
in
pkgs.stdenv.mkDerivation {
  name = "myenv";
  buildInputs = with pkgs; [
      pkgs_old.libbpf
      clang-tools_18
      clang-format-18
      llvmPackages_18.bintools
      llvm_18
      clang_18
      bpftools
      bear
  ];
  shellHook =
    ''
      export BPF2GO_CC=clang-18
      export BPF2GO_STRIP=llvm-strip
    '';
}
