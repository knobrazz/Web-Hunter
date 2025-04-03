from setuptools import setup, find_packages

setup(
    name="webhunter",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "click>=8.0.0",
        "rich>=10.0.0",
        "requests>=2.26.0",
        "python-nmap>=0.7.1",
        "pyyaml>=5.4.1",
    ],
    entry_points={
        "console_scripts": [
            "webhunter=webhunter.cli:main",
        ],
    },
)

