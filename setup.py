from setuptools import setup, find_packages

setup(
    name="ossbomer-oslc",
    version="1.0.0",
    author="Oscar Valenzuela",
    author_email="oscar.valenzuela.b@gmail.com",
    description="OSSBOMER - Open Source License Compliance verification using Open Source Software Advisories and License SPDX rules.",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "ossbomer_oslc": [
            "license_rules.json",
            "ossa_data/*.*",
        ]
    },
    install_requires=[
        "click>=8.0",
        "jsonschema>=4.0",
    ],
    entry_points={
        "console_scripts": [
            "ossbomer-oslc=ossbomer_oslc.cli:validate",
        ]
    },
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
    ],
    python_requires=">=3.7",
)
