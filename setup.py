from setuptools import find_packages, setup

setup(
    name="crumb-cli",
    version="0.1.0",
    packages=find_packages(),
    install_requires=["tldextract", "argon2-cffi"],
    entry_points={"console_scripts": ["crumb=crumb.cli:main"]},
    python_requires=">=3.9",
)
