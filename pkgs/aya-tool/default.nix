{ rustPlatform
, version
, hash
, cargoHash
, fetchFromGitHub
, cargo
, cacert
,
}:
rustPlatform.buildRustPackage {
  pname = "aya-tool";
  version = version;
  src = fetchFromGitHub {
    owner = "aya-rs";
    repo = "aya";
    rev = "aya-v${version}";
    #hash = pkgs.lib.fakeHash;
    hash = hash;

    nativeBuildInputs = [
      cargo
      cacert
    ];
    postFetch = ''
      pushd $out
        cargo generate-lockfile --manifest-path ./Cargo.toml
      popd
    '';
  };

  doCheck = false;
  useFetchCargoVendor = true;
  cargoHash = cargoHash;
}
