{
  description = "A very basic flake";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        overrides = (builtins.fromTOML (builtins.readFile (self + "/rust-toolchain.toml")));
        libPath = with pkgs; lib.makeLibraryPath [
          # load external libraries that you need in your rust project here
        ];
        aya-tool = import ./pkgs/aya-tool/default.nix {
          inherit (pkgs) fetchFromGitHub cargo cacert rustPlatform;
          version = "0.13.1";
          hash = "sha256-A2lUMbQes7ysO8FU1/oH1hEGSZhlNl8LEqxDC5BM8G0=";
          cargoHash = "sha256-rIfOMTZZA6ZtrxqMsPjNpVAm7NY0hzFPEutQc9JUOdI=";
        };

      in
      {
        #rec required to access buildInputs and nativeBuildInputs within the mkShell
        devShells.default = pkgs.mkShell rec {
          buildInputs = with pkgs; [
            clang
            rustup
            llvmPackages.bintools
            cargo-generate
            bpf-linker
            aya-tool
          ];
          nativeBuildInputs = [ pkgs.pkg-config ];
          packages = with pkgs;[
            rustup
          ];
          RUSTC_VERSION = overrides.toolchain.channel;
          LIBCLANG_PATH = pkgs.lib.makeLibraryPath [ pkgs.llvmPackages_latest.libclang.lib ];
          shellHook = ''
            export PATH=$PATH:''${CARGO_HOME:-~/.cargo}/bin
            export PATH=$PATH:''${RUSTUP_HOME:-~/.rustup}/toolchains/$RUSTC_VERSION-x86_64-unknown-linux-gnu/bin/
          '';
          LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath (buildInputs ++ nativeBuildInputs);

          # Add glibc, clang, glib, and other headers to bindgen search path
          BINDGEN_EXTRA_CLANG_ARGS =
            # Includes normal include path
            (builtins.map (a: ''-I"${a}/include"'') [
              # add dev libraries here (e.g. pkgs.libvmi.dev)
              pkgs.glibc.dev
            ])
            # Includes with special directory paths
            ++ [
              ''-I"${pkgs.llvmPackages_latest.libclang.lib}/lib/clang/${pkgs.llvmPackages_latest.libclang.version}/include"''
              ''-I"${pkgs.glib.dev}/include/glib-2.0"''
              ''-I${pkgs.glib.out}/lib/glib-2.0/include/''
            ];

        };
      }
    );
}
