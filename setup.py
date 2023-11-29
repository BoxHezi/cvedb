from setuptools import setup, find_packages
from cvedb.version import __version__

long_desc = ""
with open("./README.md", "r") as file:
    for line in file:
        long_desc += line

setup(
    name="py-cvedb",
    version=__version__,
    packages=find_packages(),
    author="Box Hezi",
    author_email="hezipypi.yixdpu@bumpmail.io",
    description="A simple CVE database written in Python",
    long_description=long_desc,
    long_description_content_type="text/markdown",
    url="https://github.com/BoxHezi/cvedb",
    install_requires=[
        "nvdlib",
        "tqdm",
        "pgzip"
    ],
    entry_points={
        'console_scripts': [
            'cvedb = cvedb.cvedb:main'
        ]
    }
)