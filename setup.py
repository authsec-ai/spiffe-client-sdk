from setuptools import setup, find_packages

setup(
    name="spiffe-client-sdk",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "aiohttp",
        "spiffe",
        "cryptography",
        "pydantic",
        "python-dateutil",
    ],
    python_requires=">=3.10.11",
    author="AuthSec",
    description="SPIFFE Client SDK for Python (Async)",
    url="https://github.com/authsec-ai/spiffe-client-sdk",
)
