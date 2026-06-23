{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    crate2nix = { url = "github:kolloch/crate2nix/master"; flake = false; };
    flake-parts.url = "github:hercules-ci/flake-parts";
  };

  outputs = { self, nixpkgs,  crate2nix, flake-parts } @ inputs : flake-parts.lib.mkFlake { inherit inputs; } {
    perSystem = { config, self', inputs', pkgs, system, ... }:
      let
      pkgs = import nixpkgs {
        inherit system;
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
        packages = with pkgs; [ rust-analyzer cargo rustc ];
      };
      in {
        devShells.default = devShell;
        packages = {
          default = cargoNix.workspaceMembers.rustables.build;
          rustables = cargoNix.workspaceMembers.rustables.build;
        };
      };

      systems = [ "x86_64-linux" "aarch64-linux" ];
  };
}
