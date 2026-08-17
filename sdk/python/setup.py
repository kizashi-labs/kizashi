from setuptools import setup, find_packages

setup(
    name="kizashi-edr-client",
    version="1.0.0",
    description="Official Python client SDK for the Kizashi API",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="camel",
    url="https://github.com/kizashi-labs/kizashi",
    project_urls={
        "Source": "https://github.com/kizashi-labs/kizashi",
        "Issues": "https://github.com/kizashi-labs/kizashi/issues",
    },
    license="AGPL-3.0-or-later",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[],  # No external dependencies
    extras_require={
        "dev": ["pytest>=7.0", "pytest-cov>=4.0"],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    keywords=["edr", "endpoint-detection-response", "security", "kizashi"],
)
