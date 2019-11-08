# -*- coding: utf-8 -*-
from setuptools import setup, find_packages

with open("README.md") as f:
    readme = f.read()

setup(
    name="casdapy",
    version="0.1.0",
    description="Provides functions to search for and download data products from CASDA.",
    long_description=readme,
    author="Andrew O'Brien",
    author_email="obrienan@uwm.edu",
    url="https://github.com/askap-vast/casdapy",
    python_requires=">=3.6",
    install_requires=[
        "astropy",
        "click",
        "pandas",
        "requests",
        "tqdm",
    ],
    packages=find_packages(),
    package_data={
        "casdapy.scripts": ["logger_config.json"],
    },
    entry_points={
        "console_scripts": ["casda_download=casdapy.scripts.download:main"],
    },
)
