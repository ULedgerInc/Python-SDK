#! /usr/bin/env python3

from setuptools import setup

setup(
    name='uledger',
    version='0.2.5',
    description='A Python SDK for the ULedger API',
    license='Apache License 2.0',
    author='Jackson Parsons',
    author_email='jackson@uledger.co',
    url='https://github.com/ULedgerInc/Python-SDK',
    packages=['uledger'],
    install_requires=['requests', 'requests_toolbelt', 'pymultihash', 'base58'],
    python_requires='>=3.5'
)
