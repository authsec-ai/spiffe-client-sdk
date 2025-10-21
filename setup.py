from setuptools import setup, find_packages

setup(
    name="spiffe-client-sdk",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "aiohttp>=3.9.0",
        "spiffe>=0.2.0",
        "cryptography>=41.0.0",
        "pydantic>=2.0.0",
        "python-dateutil>=2.8.2",
    ],
    python_requires=">=3.11",
    author="AuthSec",
    description="SPIFFE Client SDK for Python (Async)",
    url="https://github.com/authsec-ai/spiffe-client-sdk",
)
