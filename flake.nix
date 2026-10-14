{
  description = "Development tools for sustainablelobster.legacy_windows";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
  inputs.sansldap = {
    url = "github:jborean93/sansldap/v0.1.0";
    flake = false;
  };

  outputs =
    { nixpkgs, sansldap, ... }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      # Upstream AD's controller inventory uses this library, absent from nixpkgs.
      sansldapPackage = pkgs.python3Packages.buildPythonPackage {
        pname = "sansldap";
        version = "0.1.0";
        src = sansldap;
        pyproject = true;
        build-system = [ pkgs.python3Packages.setuptools ];
        pythonImportsCheck = [ "sansldap" ];
      };
      python = pkgs.python3.withPackages (
        packages: with packages; [
          ansible-core
          black
          isort
          mypy
          pre-commit-hooks
          pylint
          sansldapPackage
          pyspnego
          dnspython
          cryptography
          krb5
          pyftpdlib
          pytest
          yamllint
        ]
      );
    in
    {
      devShells.${system}.default = pkgs.mkShellNoCC {
        packages = [
          python
          pkgs.actionlint
          pkgs.ansible-lint
          pkgs.codespell
          pkgs.gh
          pkgs.git
          pkgs.just
          pkgs.nixfmt
          pkgs.openssl
          pkgs.openssh
          pkgs.pre-commit
          pkgs.rumdl
          pkgs.shellcheck
          pkgs.vermin
        ];
      };
      formatter.${system} = pkgs.nixfmt;
    };
}
