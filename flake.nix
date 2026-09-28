{
  description = "Development tools for sustainablelobster.legacy_windows";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs =
    { nixpkgs, ... }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      python = pkgs.python3.withPackages (
        packages: with packages; [
          ansible-core
          black
          isort
          mypy
          pre-commit-hooks
          pylint
          pytest
          yamllint
        ]
      );
    in
    {
      devShells.${system}.default = pkgs.mkShellNoCC {
        packages = [
          python
          pkgs.ansible-lint
          pkgs.codespell
          pkgs.git
          pkgs.just
          pkgs.nixfmt
          pkgs.pre-commit
          pkgs.rumdl
          pkgs.vermin
        ];
      };
      formatter.${system} = pkgs.nixfmt;
    };
}
