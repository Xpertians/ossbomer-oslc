import json
import os
import unittest
import tempfile
from ossbomer_oslc.validator import LicenseValidator, PackageRiskAnalyzer

class TestLicenseValidator(unittest.TestCase):
    def setUp(self):
        """Set up temporary license rules file."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.license_file = os.path.join(self.temp_dir.name, "license_rules.json")

        TEST_LICENSE_RULES = {
            "licenses": [{"spdx_id": "GPL-3.0", "aliases": []}, {"spdx_id": "MIT", "aliases": []}]
        }

        with open(self.license_file, "w") as f:
            json.dump(TEST_LICENSE_RULES, f)

        self.validator = LicenseValidator(self.license_file)

    def tearDown(self):
        """Cleanup temporary files."""
        self.temp_dir.cleanup()

    def test_license_validation(self):
        """Test valid and invalid licenses."""
        TEST_SBOM = {
            "components": [
                {"name": "componentA", "license": "GPL-3.0"},
                {"name": "componentB", "license": "Unknown-License"}
            ]
        }

        results = self.validator.validate(TEST_SBOM)
        self.assertEqual(results["componentA"], "Valid")
        self.assertEqual(results["componentB"], "Invalid")

class TestPackageRiskAnalyzer(unittest.TestCase):
    def setUp(self):
        """Set up temporary OSSA dataset folder."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.ossa_folder = os.path.join(self.temp_dir.name, "ossa_data")
        os.makedirs(self.ossa_folder)

        TEST_OSSA_DATA = {
            "purls": ["pkg:rpm/amzn/componentA@1.0"],
            "severity": "High"
        }

        ossa_file = os.path.join(self.ossa_folder, "ossa_test.json")
        with open(ossa_file, "w") as f:
            json.dump(TEST_OSSA_DATA, f)

        self.analyzer = PackageRiskAnalyzer(self.ossa_folder)

    def tearDown(self):
        """Cleanup temporary files."""
        self.temp_dir.cleanup()

    def test_package_risk_analysis(self):
        """Test risk analysis for known and unknown packages."""
        TEST_SBOM = {
            "components": [
                {"name": "componentA", "purl": "pkg:rpm/amzn/componentA@1.0"},
                {"name": "componentB", "purl": "pkg:rpm/amzn/componentB@2.0"}
            ]
        }

        results = self.analyzer.analyze(TEST_SBOM)
        self.assertEqual(results["componentA"], "High")
        self.assertEqual(results["componentB"], "Unknown")

if __name__ == "__main__":
    unittest.main()