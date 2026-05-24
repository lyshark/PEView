import setuptools
from distutils.core import setup

packages = ['peview_client']

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name='peview_client',
    version='4.0.0',
    author='lyshark',
    description='A PE file analysis tool developed for Windows platforms, used to quickly parse PE (Portable Executable) file structures, disassemble code segments, convert virtual addresses/relative virtual addresses/file offset addresses, search signatures/strings, and assist in reverse engineering, malware analysis, and exploit development.',
    long_description=long_description,
    long_description_content_type="text/markdown",
    author_email='me@lyshark.com',
    url="http://peview.lyshark.com",
    python_requires=">=3.6.0",
    license="MIT Licence",
    packages=packages,
    include_package_data=True,
    platforms="any",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        # Add any dependencies here
    ],
)
