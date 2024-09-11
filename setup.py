from setuptools import setup

setup(
    name="bitwarden-wrapper",
    version="0.1.15",
    author="Vasily Kleschov",
    author_email="kleshev12@gmail.com",
    description="The python wrapper around Bitwarden CLI.",
    url="https://github.com/AlmaLinux/py-bitwarden-wrapper",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    packages=['bsbw'],
    install_requires=[
        'cryptography',
        'jmespath>=0.10.0',
        'plumbum==1.8.2',
        'pydantic',
    ],
    python_requires=">=3.6",
    setup_requires=['setuptools>=65.5.1'],
)
