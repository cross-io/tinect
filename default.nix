{
  lib,
  stdenv,
  rustPlatform,
  pkg-config,
  libmnl,
  libnftnl,
}:
rustPlatform.buildRustPackage {
  pname = "tinect";
  version = (lib.importTOML ./Cargo.toml).package.version;

  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./Cargo.toml
      ./Cargo.lock
      ./build.rs
      ./examples
      ./src
      ./crates
    ];
  };

  cargoLock = {
    lockFile = ./Cargo.lock;
    outputHashes = {
      "pfctl-0.7.0" = "sha256-yMI1Lx1aAV5wBTLM3a1MQBUjvjc44AtppzlFanFAoUM=";
    };
  };

  nativeBuildInputs = [ pkg-config ];
  buildInputs = lib.optionals stdenv.hostPlatform.isLinux [
    libmnl
    libnftnl
  ];

  meta = {
    description = "A static, policy-driven layer-3 overlay network";
    homepage = "https://github.com/cross-io/tinect";
    license = lib.licenses.asl20;
    mainProgram = "tinect";
  };
}
