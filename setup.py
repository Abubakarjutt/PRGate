"""Leaves the prgate.sandbox module out of the wheel.

All metadata lives in pyproject.toml. setuptools has no setting that drops one module from a package
(`exclude-package-data` only covers data files), so build_py filters it here."""
from setuptools import setup
from setuptools.command.build_py import build_py

PRIVATE_MODULES = {("prgate", "sandbox")}


class BuildPy(build_py):
    def find_package_modules(self, package, package_dir):
        modules = super().find_package_modules(package, package_dir)
        return [m for m in modules if (m[0], m[1]) not in PRIVATE_MODULES]


setup(cmdclass={"build_py": BuildPy})
