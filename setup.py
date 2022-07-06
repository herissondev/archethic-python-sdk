from setuptools import setup, find_packages
import setuptools


VERSION = "0.0.0.4"
DESCRIPTION = "ArchEthic Python SDK"

with open("README.md", "r", encoding="utf-8") as fh:
    LONG_DESCRIPTION = fh.read()

# Setting up
setup(
    name="archethic",
    version=VERSION,
    author="Aimé Risson",
    author_email="aime.risson.1@gmail.fr",
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    install_requires=["PyNaCl", "libnacl", "requests", "pycryptodomex", "gql", "websockets", "fastecdsa", "secp256k1", "requests_toolbelt"],
    keywords=["python", "crypto", "archethic", "python archethic", "UCO"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Intended Audience :: Education",
    ],
    package_dir={"": "src"},
    packages=setuptools.find_packages(where="src"),
    python_requires=">=3.6",
    url="https://github.com/aime-risson/archethic-python-sdk",
)
