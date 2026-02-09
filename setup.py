"""Setup configuration for SNARKs package."""
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="snarks",
    version="0.1.0",
    author="Marco Simoncini",
    description="Simplified, theory-based implementations of zk-SNARK proof systems",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Aslan-256/SNARKs",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Education",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "numpy>=1.21.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-benchmark>=4.0.0",
        ],
    },
)
