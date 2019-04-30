import os
import setuptools

directory = os.path.abspath(os.path.dirname(__file__))
with open(directory + os.path.sep + "README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="snmp",
    version="0.1.4",
    author="Charles Tolley",
    author_email="charlestolley@gmail.com",
    license="GPLv3+",
    description="A minimal SNMP implementation",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/charlestolley/python-snmp",
    packages=setuptools.find_packages(),
    python_requires=">=3, <4",
    classifiers=[
        "Programming Language :: Python :: 3 :: Only",
        "Development Status :: 2 - Pre-Alpha",
        "Operating System :: POSIX :: Linux",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Intended Audience :: Information Technology",
        "Topic :: System :: Networking",
        "Natural Language :: English",
    ],
)
