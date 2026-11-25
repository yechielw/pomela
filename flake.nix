{
  description = "Pomela: headless Entra SSO and Citrix desktop launcher";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { nixpkgs, ... }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      inherit (pkgs) lib;
    in
    {
      packages.${system}.default = pkgs.buildGoModule {
        pname = "pomela";
        version = "0.1.0";

        # Exclude credentials, local configuration, ICA tickets and binaries.
        src = lib.fileset.toSource {
          root = ./.;
          fileset = lib.fileset.fileFilter (
            file:
            file.hasExt "go"
            || builtins.elem file.name [
              "go.mod"
              "go.sum"
              "LICENSE"
              "pomela.png"
              "pomela.desktop"
            ]
          ) ./.;
        };

        vendorHash = "sha256-CwWCk7ZCBXcFX8hZlF78EStmsAKNbwUkb5DgTVSeQlM=";

        ldflags = [ "-X=main.dialogCommand=${lib.getExe pkgs.zenity}" ];

        postInstall = ''
          install -Dm644 LICENSE "$out/share/licenses/pomela/LICENSE"
          install -Dm644 pomela.desktop "$out/share/applications/pomela.desktop"
          install -Dm644 pomela.png "$out/share/pixmaps/pomela.png"
          substituteInPlace "$out/share/applications/pomela.desktop" \
            --replace-fail "Exec=pomela" "Exec=$out/bin/pomela"
        '';

        meta = {
          description = "Headless Entra SSO and Citrix desktop launcher";
          mainProgram = "pomela";
          license = lib.licenses.mit;
          platforms = [ system ];
        };
      };
    };
}
