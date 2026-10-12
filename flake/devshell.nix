{ inputs, ... }:
{
  perSystem =
    {
      config,
      lib,
      pkgs,
      self',
      system,
      ...
    }:
    let
      codecovPkgs = import inputs.nixpkgs {
        inherit system;
        config.allowUnfreePredicate = pkg: builtins.elem (lib.getName pkg) [ "test-results-parser" ];
      };

      linuxLibraries = lib.optionals pkgs.stdenv.hostPlatform.isLinux [
        pkgs.libmnl
        pkgs.libnftnl
      ];

      linuxTestTools = lib.optionals pkgs.stdenv.hostPlatform.isLinux [
        pkgs.conntrack-tools
        pkgs.iproute2
        pkgs.iputils
        pkgs.nftables
        pkgs.strace
        pkgs.tcpdump
      ];

      linuxCiTools = lib.optionals pkgs.stdenv.hostPlatform.isLinux [
        codecovPkgs.codecov-cli
      ];

      pkgConfigPath = lib.optionalString pkgs.stdenv.hostPlatform.isLinux (
        lib.concatStringsSep ":" [
          "${pkgs.libmnl}/lib/pkgconfig"
          "${pkgs.libnftnl}/lib/pkgconfig"
        ]
      );
    in
    {
      devShells.default = pkgs.mkShell {
        inputsFrom = [ self'.packages.tinect ];
        packages = [
          config.treefmt.build.wrapper
          pkgs.bash
          pkgs.cargo
          pkgs.clippy
          pkgs.curl
          pkgs.gawk
          pkgs.gnupg
          pkgs.llvmPackages.llvm
          pkgs.pkg-config
          pkgs.python3
          pkgs.rust-analyzer
          pkgs.rustc
          pkgs.rustfmt
          pkgs.shellcheck
          pkgs.xz
        ]
        ++ linuxLibraries
        ++ linuxTestTools
        ++ linuxCiTools;
        LLVM_COV = "${pkgs.llvmPackages.llvm}/bin/llvm-cov";
        LLVM_PROFDATA = "${pkgs.llvmPackages.llvm}/bin/llvm-profdata";
        PKG_CONFIG_PATH = pkgConfigPath;
      };
    };
}
