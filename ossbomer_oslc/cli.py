import json
import xml.etree.ElementTree as ET
import click
import os
from ossbomer_oslc.validator import LicenseValidator, PackageRiskAnalyzer

DEFAULT_LICENSE_RULES = os.path.join(os.path.dirname(__file__), "license_rules.json")
DEFAULT_OSSA_FOLDER = os.path.join(os.path.dirname(__file__), "ossa_data")

def detect_sbom_format(sbom_file):
    """Detect if the SBOM is SPDX or CycloneDX and if it is JSON or XML."""
    try:
        with open(sbom_file, "r") as f:
            first_chars = f.read(10).strip()
            if first_chars.startswith("{"):
                f.seek(0)
                data = json.load(f)
                if "SPDXID" in data:
                    return "spdx", "json"
                elif "bomFormat" in data and data["bomFormat"] == "CycloneDX":
                    return "cyclonedx", "json"
            elif first_chars.startswith("<"):
                tree = ET.parse(sbom_file)
                root = tree.getroot()
                if "SPDX" in root.tag:
                    return "spdx", "xml"
                elif "bom" in root.tag:
                    return "cyclonedx", "xml"
    except Exception as e:
        click.echo(f"Error detecting SBOM format: {e}", err=True)
        exit(1)
    return None, None

@click.command()
@click.option("--file", "sbom_file", required=True, help="Path to SBOM file (JSON or XML format)")
@click.option("--license-rules", "license_file", default=DEFAULT_LICENSE_RULES, help="Path to custom license rules file")
@click.option("--ossa-folder", "ossa_folder", default=DEFAULT_OSSA_FOLDER, help="Path to OSSA JSON dataset folder")
@click.option("--use-case", "use_case", default="distribution", type=click.Choice(["internal", "distribution"]), help="Specify use case: internal or distribution (default: distribution)")
@click.option("--min-severity", "min_severity", default=None, help="Minimum severity level to display (Informational, Low, Medium, High, Critical)")
@click.option("--json-output", is_flag=True, help="Output results in JSON format")
def validate(sbom_file, license_file, ossa_folder, use_case, min_severity, json_output):
    try:
        sbom_type, sbom_format = detect_sbom_format(sbom_file)
        if not sbom_type:
            click.echo("Error: Unsupported SBOM format", err=True)
            exit(1)
        
        if sbom_format == "json":
            with open(sbom_file, "r") as f:
                sbom_data = json.load(f)
        else:
            sbom_data = ET.parse(sbom_file).getroot()
        
        num_components = len(sbom_data.get("components", [])) if sbom_format == "json" else len(sbom_data.findall(".//component"))
        click.echo(f"Processing {num_components} components for license validation and package risk analysis...\n")
        
        license_validator = LicenseValidator(license_file, use_case)
        package_analyzer = PackageRiskAnalyzer(ossa_folder, min_severity)

        license_results = license_validator.validate(sbom_data)
        risk_results = package_analyzer.analyze(sbom_data)

        results = {
            "license_validation": license_results,
            "package_risk_analysis": risk_results
        }

        if json_output:
            click.echo(json.dumps(results, indent=4))
        else:
            if license_results:
                click.echo("License Validation:")
                for component, issues in license_results.items():
                    click.echo(f"  {component}:")
                    for issue in issues:
                        click.echo(f"    - {issue}")
                click.echo("")
            
            if risk_results:
                click.echo("Package Risk Analysis:")
                for component, risks in risk_results.items():
                    click.echo(f"  {component}:")
                    for risk in risks:
                        click.echo(f"    - Severity: {risk['severity']}, Title: {risk['title']}, ID: {risk['id']}, Match Type: {risk['match_type']}")

    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        exit(1)

if __name__ == "__main__":
    validate()
