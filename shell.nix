{pkgs ? import <nixpkgs> {}}:
pkgs.mkShellNoCC {
  packages = with pkgs; [
    go
    gnumake
    gotools
    gopls
  ];
}
