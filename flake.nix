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
          channel = "1.65.0";
          sha256 = "DzNEaW724O8/B8844tt5AVHmSjSQ3cmzlU4BP90oRlY=";
        };
      in
      {
        inherit rustChannel;
        rustc = rustChannel.rust;
        cargo = rustChannel.rust;
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
      in {
        defaultPackage = cargoNix.rootCrate.build;
        packages = {
          rustables = cargoNix.rootCrate.build;
        };
        devShell = pkgs.mkShell {
          name = "rustables";
          nativeBuildInputs = nativeBuildInputs;
          buildInputs = buildInputs;
          LIBCLANG_PATH = LIBCLANG_PATH;
          packages = with pkgs; [ rust-analyzer rustc-with-src ];
        };
      }
    );
}
