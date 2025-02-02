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

        self.validator = LicenseValidator(self.license_file, use_case="distribution")

    def tearDown(self):
        """Cleanup temporary files."""
        self.temp_dir.cleanup()

    def test_license_validation(self):
        """Test invalid licenses are flagged, and valid licenses do not appear."""
        TEST_SBOM = {
            "components": [
                {"name": "componentA", "licenses": [{"license": {"id": "GPL-3.0"}}]},
                {"name": "componentB", "licenses": [{"license": {"id": "Unknown-License"}}]}
            ]
        }

        results = self.validator.validate(TEST_SBOM)
        self.assertNotIn("componentA", results)
        self.assertIn("componentB", results)
        self.assertIn("No guidance available for license 'Unknown-License'", results["componentB"])

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
        """Test that only flagged risks appear in results."""
        TEST_SBOM = {
            "components": [
                {"name": "componentA", "purl": "pkg:rpm/amzn/componentA@1.0"},
                {"name": "componentB", "purl": "pkg:rpm/amzn/componentB@2.0"}
            ]
        }

        results = self.analyzer.analyze(TEST_SBOM)
        self.assertIn("componentA", results)
        self.assertNotIn("componentB", results)
        self.assertEqual(results["componentA"][0]["severity"], "High")

if __name__ == "__main__":
    unittest.main()
