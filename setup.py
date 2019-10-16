# -*- coding: utf-8 -*-
from setuptools import setup, find_packages

with open("README.md") as f:
    readme = f.read()

setup(
    name="casdapy",
    version="0.1.0",
    description="Provides functions to download data products from CASDA.",
    long_description=readme,
    author="Andrew O'Brien",
    author_email="obrienan@uwm.edu",
    url="",
    packages=find_packages(),
    entry_points={
        "console_scripts": ["casda_download_sbid=casdapy.download:main"],
    },
)
