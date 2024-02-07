{
  description = "go-secure-sdk";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, utils }:
    utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };
      in
      rec
      {
        devShells = {
          default = pkgs.mkShell
              {
                buildInputs = [
                  pkgs.go_1_21
                  pkgs.gotestsum
                  pkgs.golangci-lint
                  pkgs.mockgen
                  pkgs.gofumpt
                  pkgs.gci
                  pkgs.just
                  pkgs.cyclonedx-gomod
                  pkgs.goreleaser
                  pkgs.cosign
                  pkgs.go-licenses
                ];
              };
        };
      }
    );
}
