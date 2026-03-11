{
  description = "A very basic flake";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
  }:
    flake-utils.lib.eachDefaultSystem
    (
      system: let
        pkgs = import nixpkgs {
          inherit system;
        };
      in
        with pkgs; {
          devShells = {
            default = mkShell {
              buildInputs = [llvmPackages_18.clang-tools libbpf llvmPackages_18.clang-unwrapped llvmPackages_18.llvm bpftools bear];
              nativeBuildInputs = [linuxHeaders];
              hardeningDisable = ["all"];
              NIX_CFLAGS_COMPILE = ["-Wno-unused-command-line-argument"];
            };
          };
        }
    );
}
