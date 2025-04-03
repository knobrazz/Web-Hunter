from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="webhunter",
    version="1.0.0",
    author="Nabaraj Lamichhane",
    author_email="nabarajlamichhane721@gmail.com",
    description="Advanced automated reconnaissance tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/knobrazz/webhunter",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "webhunter=webhunter.cli:cli",
        ],
    },
)

