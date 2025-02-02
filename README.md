# ossbomer-oslc

**ossbomer-oslc** is a Python library and CLI tool that perform Open Source License Compliance against SBOM (Software Bill of Materials) using License Rules and Open Source Software Advisory from Xpertians.

## Features
* Supports SPDX & CycloneDX SBOMs in both JSON and XML formats.
* License Validation using SPDX identifiers and custom rules.
* Package Risk Analysis based on Open Source Software Advisory from Xpertians.
* CLI & Library Support for automation or interactive use.
* Severity Filtering for risk levels (Informational, Low, Medium, High, Critical).

## Installation

```
pip install ossbomer-oslc
```

## Usage
CLI Usage to Validate an SBOM file:

```
$ ossbomer-oslc --file sbom.json --json-output
$ ossbomer-oslc --file tests/test_sbom.json --use-case distribution --min-severity Medium --json-output
```

Specify a custom rules file:

```
ossbomer-conformance --file sbom.json --rules custom_rules.json
```

Library Integration:

```
import json
from ossbomer_oslc.validator import LicenseValidator, PackageRiskAnalyzer

license_validator = LicenseValidator("license_rules.json", use_case="distribution")
package_analyzer = PackageRiskAnalyzer("ossa_data/")

with open("sbom.json", "r") as f:
    sbom_data = json.load(f)
license_results = license_validator.validate(sbom_data)
risk_results = package_analyzer.analyze(sbom_data)

print("License Issues:", license_results)
print("Package Risks:", risk_results)
```

## Customization

### License Rules:
Defines which licenses are allowed or restricted for different use cases (internal, distribution, or any other use case you have).

```
{
    "licenses": [
        {
            "spdx_id": "GPL-3.0",
            "aliases": [],
            "use_case": {
                "internal": true,
                "distribution": false,
                "development": true
                "laptop": true
            }
        },
        {
            "spdx_id": "MIT",
            "aliases": [],
            "use_case": {
                "internal": true,
                "distribution": true,
                "development": true,
                "laptop": true
            }
        }
    ]
}
```

### Open Source Software Advisory for Package Risk Assessment:
You can find more information in the [Open Source Software Advisory website](https://github.com/Xpertians/OpenSourceAdvisoryDatabase)


### License
This project is licensed under the MIT License.