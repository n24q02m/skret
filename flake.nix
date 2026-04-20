{
  description = "skret — cloud-provider secret manager CLI";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        version = "1.0.0";
      in
      {
        packages.default = pkgs.buildGoModule {
          pname = "skret";
          inherit version;

          src = pkgs.lib.cleanSource ./.;

          # vendorHash placeholder. First `nix build` prints the real
          # hash in the error message — paste it here and commit. Keep
          # `pkgs.lib.fakeHash` when bumping module versions so nix
          # surfaces the new hash instead of silently reusing cache.
          vendorHash = pkgs.lib.fakeHash;

          subPackages = [ "cmd/skret" ];

          ldflags = [
            "-s"
            "-w"
            "-X github.com/n24q02m/skret/internal/version.Version=${version}"
          ];

          doCheck = false;  # Full Go suite runs via CI, not nix build.

          meta = with pkgs.lib; {
            description = "Cloud-provider secret manager CLI with Doppler/Infisical-grade DX";
            homepage = "https://skret.n24q02m.com";
            license = licenses.mit;
            maintainers = [ ];
            mainProgram = "skret";
            platforms = platforms.unix ++ platforms.windows;
          };
        };

        devShells.default = pkgs.mkShell {
          buildInputs = [
            pkgs.go_1_26 or pkgs.go
            pkgs.golangci-lint
            pkgs.gofumpt
            pkgs.pre-commit
          ];
        };
      });
}
