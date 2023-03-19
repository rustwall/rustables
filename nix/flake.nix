{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    nixpkgs-mozilla = { url = "github:mozilla/nixpkgs-mozilla"; flake = false; };
    crate2nix = { url = "github:kolloch/crate2nix/master"; flake = false; };
    utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, nixpkgs-mozilla, crate2nix, utils } @ inputs :
    let
    rustOverlay = (final: prev:
      let
        rustChannel = prev.rustChannelOf {
          channel = "1.66.0";
          sha256 = "S7epLlflwt0d1GZP44u5Xosgf6dRrmr8xxC+Ml2Pq7c=";
        };
        rust = rustChannel.rust.override {
          targets = [ "x86_64-unknown-linux-musl" ];
        };
      in
      {
        rustc = rust;
        cargo = rust;
      }
    );
    rustDevOverlay = final: prev: {
      # rust-analyzer needs core source
      rustc-with-src = prev.rustc.override { extensions = [ "rust-src" ]; };
    };
    in
    utils.lib.eachDefaultSystem (system:
      let
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ (import "${nixpkgs-mozilla}/rust-overlay.nix") rustOverlay rustDevOverlay ];
      };
      nativeBuildInputs = with pkgs; [ pkg-config ];
      buildInputs = with pkgs; [ clang linuxHeaders ];
      LIBCLANG_PATH = pkgs.lib.makeLibraryPath [ pkgs.llvmPackages_latest.libclang.lib ];
      customBuildCrate = pkgs: pkgs.buildRustCrate.override {
        defaultCrateOverrides = pkgs.defaultCrateOverrides // {
          rustables = attrs: {
            nativeBuildInputs = nativeBuildInputs;
            buildInputs = buildInputs;
            LIBCLANG_PATH = LIBCLANG_PATH;
          };
        };
      };
      cargoNix = import ./Cargo.nix { 
        inherit pkgs; 
        buildRustCrateForPkgs = customBuildCrate;
        release = false;
      };
      devShell = pkgs.mkShell {
        name = "rustables";
        nativeBuildInputs = nativeBuildInputs;
        buildInputs = buildInputs;
        LIBCLANG_PATH = LIBCLANG_PATH;
        packages = with pkgs; [ rust-analyzer rustc-with-src ];
      };
      in {
        defaultPackage = cargoNix.rootCrate.build;
        devShells.default = devShell;
        packages = {
          rustables = cargoNix.rootCrate.build;
        };
      }
    );
}
