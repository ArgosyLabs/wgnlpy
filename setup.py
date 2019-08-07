#!/usr/bin/env python3
from setuptools import setup

from os import path
this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name = "wgnlpy",
    version = "0.0.1",
    description = ("Netlink connector to WireGuard"),
    url = "https://github.com/ArgosyLabs/wgnlpy",
    author = "Derrick Lyndon Pallas",
    author_email = "derrick@argosylabs.com",
    license = "MIT",
    packages = [ "wgnlpy", "wgnlpy/nlas" ],
    install_requires = [ "pyroute2" ],
    long_description = long_description,
    long_description_content_type = "text/markdown",
    keywords = "wireguard netlink sockaddr sockaddr_in sockaddr_in6",
    classifiers = [
        "Development Status :: 3 - Alpha",
        "Programming Language :: Python :: 3 :: Only",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Networking",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
    ],
    include_package_data=True,
)
#
