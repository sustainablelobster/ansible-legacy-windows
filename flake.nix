{
  description = "Development tools for the sustainablelobster legacy Windows collections";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
  inputs.sansldap = {
    url = "github:jborean93/sansldap/v0.1.0";
    flake = false;
  };
  inputs.pypsexec = {
    url = "github:jborean93/pypsexec/v0.3.0";
    flake = false;
  };
  inputs.actionlint-queue-patch = {
    url = "file+https://github.com/rhysd/actionlint/commit/644076a59742c2d1540ebd4686eab3c308f0e562.patch";
    flake = false;
  };

  outputs =
    {
      nixpkgs,
      sansldap,
      pypsexec,
      actionlint-queue-patch,
      ...
    }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      # Upstream PR 654 adds GitHub's queue syntax without relaxing other checks.
      actionlint = pkgs.actionlint.overrideAttrs (previous: {
        patches = (previous.patches or [ ]) ++ [ actionlint-queue-patch ];
      });
      # Upstream AD's controller inventory uses this library, absent from nixpkgs.
      sansldapPackage = pkgs.python3Packages.buildPythonPackage {
        pname = "sansldap";
        version = "0.1.0";
        src = sansldap;
        pyproject = true;
        build-system = [ pkgs.python3Packages.setuptools ];
        pythonImportsCheck = [ "sansldap" ];
      };
      # The upstream SMB execution module needs this controller-only library.
      pypsexecPackage = pkgs.python3Packages.buildPythonPackage {
        pname = "pypsexec";
        version = "0.3.0";
        src = pypsexec;
        pyproject = true;
        build-system = [ pkgs.python3Packages.setuptools ];
        dependencies = [ pkgs.python3Packages.smbprotocol ];
        pythonImportsCheck = [ "pypsexec.client" ];
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
          pypsexecPackage
          python-ldap
          gssapi
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
          actionlint
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
