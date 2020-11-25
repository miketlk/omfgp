from setuptools import setup, find_namespace_packages

with open("requirements.txt") as f:
    install_reqs = f.read().strip().split("\n")

setup(
    name='omfgp',
    version='0.1.1',
    license='MIT license',
    url='https://github.com/stepansnigirev/omfgp',
    description = 'oh my global platform - library to talk to manage applets on the smartcard',
    long_description="oh my global platform - library to talk to manage applets on the smartcard",
    author = 'Stepan Snigirev',
    author_email = 'snigirev.stepan@gmail.com',
    packages=find_namespace_packages("src", include=["*"]),
    package_dir={"": "src"},
    install_requires=install_reqs,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
