from os import path
from setuptools import setup
from setuptools import find_packages

version = "0.0.1"

install_requires = [
    "acme>=0.29.0",
    "certbot>=1.0.0",
    "setuptools",
    "requests",
    "mock",
    "requests-mock",
]

this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, "README.md")) as f:
    long_description = f.read()

setup(
    name="certbot-dns-qip",
    version=version,
    description="VitalQIP DNS Authenticator plugin for Certbot",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/FidelityInternational/certbot-dns-qip",
    author="Fidelity International",
    author_email="noreply@fli.com",
    license="BSD 2-Clause License",
    python_requires=">=3.5",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Plugins",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Security",
        "Topic :: System :: Installation/Setup",
        "Topic :: System :: Networking",
        "Topic :: System :: Systems Administration",
        "Topic :: Utilities",
    ],
    packages=find_packages(),
    include_package_data=True,
    install_requires=install_requires,
    entry_points={
        "certbot.plugins": [
            "dns-qip = certbot_dns_qip.dns_qip:Authenticator"
        ]
    },
    test_suite="certbot_dns_qip",
)
