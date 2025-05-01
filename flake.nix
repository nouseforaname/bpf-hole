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
        libPath = pkgs.lib.makeLibraryPath [
          # load external libraries that you need in your rust project here
        ];
        aya-tool = import ./nix/pkgs/aya-tool/default.nix {
          inherit (pkgs) fetchFromGitHub cargo cacert rustPlatform;
          version = "0.13.1";
          hash = "sha256-SKYhbtURYmQ6MgSy49Jmtxi1WzPX+wdMVN0QEYdk8LU=";
          cargoHash = "sha256-J6Ojze8AUWAHTPxqMNJIYRaHN0jMdUc+zG6nkMMtmYk=";
        };
        helpers = import nix/helpers.nix { inherit pkgs; };

      in
      {
        apps.default = {
          type = "app";
          program = "${helpers.run}/bin/run";
        };
        apps.fetch_blocklist = {
          type = "app";
          program = "${helpers.fetch_blocklist}/bin/run";
        };
        apps.dump_lo = {
          type = "app";
          program = "${helpers.dump_lo}/bin/run";
        };
        #rec required to access buildInputs and nativeBuildInputs within the mkShell
        devShells.default = pkgs.mkShell rec {

          buildInputs = with pkgs; [
            clang
            rustup
            cargo-generate
            bpf-linker
            aya-tool
          ];
          nativeBuildInputs = [ pkgs.pkg-config ];
          packages = [];
          RUSTC_VERSION = overrides.toolchain.channel;
          LIBCLANG_PATH = pkgs.lib.makeLibraryPath [ pkgs.llvmPackages_latest.libclang.lib ];
          shellHook = ''
            PATH=$PATH:''${CARGO_HOME:-~/.cargo}/bin
            PATH=$PATH:''${RUSTUP_HOME:-~/.rustup}/toolchains/$RUSTC_VERSION-x86_64-unknown-linux-gnu/bin/
            #do not use the rustup rust-analyzer. once the component is added it will try to compile it for bpfel. which won't work.
            ln -fs ${pkgs.rust-analyzer}/bin/rust-analyzer ''${rustup_home:-~/.rustup}/toolchains/nightly-x86_64-unknown-linux-gnu/bin/rust-analyzer
            ln -fs ${pkgs.rustfmt}/bin/rustfmt ''${rustup_home:-~/.rustup}/toolchains/nightly-x86_64-unknown-linux-gnu/bin/rustfmt
          '';
          LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath (buildInputs ++ nativeBuildInputs);

          # Add glibc, clang, glib, and other headers to bindgen search path
          BINDGEN_EXTRA_CLANG_ARGS =
            # Includes normal include path
            (builtins.map (a: ''-I"${a}/include"'') [
              # add dev libraries here (e.g. pkgs.libvmi.dev)
            ])
            # Includes with special directory paths
            ++ [
            ];

        };
      }
    );
}
