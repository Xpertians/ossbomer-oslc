import json
import os
import re

class LicenseValidator:
    def __init__(self, license_file, use_case="distribution"):
        self.license_file = license_file
        self.use_case = use_case
        self.licenses = self.load_licenses()

    def load_licenses(self):
        try:
            with open(self.license_file, "r") as f:
                return json.load(f).get("licenses", [])
        except (FileNotFoundError, json.JSONDecodeError):
            raise ValueError("Invalid or missing license rules file.")

    def extract_license_id(self, component):
        licenses = component.get("licenses", [])
        if isinstance(licenses, list):
            return [entry["license"].get("id") for entry in licenses if "license" in entry and "id" in entry["license"]]
        return []

    def validate(self, sbom_data):
        results = {}
        for component in sbom_data.get("components", []):
            license_ids = self.extract_license_id(component)
            issues = []
            
            if not license_ids:
                issues.append("No license found for this component")
            else:
                for license_id in license_ids:
                    license_entry = next((l for l in self.licenses if l["spdx_id"] == license_id or license_id in l.get("aliases", [])), None)
                    if not license_entry:
                        issues.append(f"No guidance available for license '{license_id}'")
                    elif not license_entry.get("use_case", {}).get(self.use_case, True):
                        issues.append(f"License '{license_id}' is not allowed for {self.use_case}")
            
            if issues:
                results[component["name"]] = issues
        return results

class PackageRiskAnalyzer:
    def __init__(self, ossa_folder, min_severity=None):
        self.ossa_folder = ossa_folder
        self.min_severity = min_severity
        self.severity_levels = {"Informational": 1, "Low": 2, "Medium": 3, "High": 4, "Critical": 5}
        self.risk_data = self.load_risk_data()

    def extract_hashes(self, component):
        hashes = {}
        for key in ["hashes", "hashSourceCodeComponent"]:
            for hash_entry in component.get(key, []):
                if "alg" in hash_entry and "content" in hash_entry:
                    hashes[hash_entry["alg"].lower()] = hash_entry["content"]
        return hashes

    def load_risk_data(self):
        risk_data = {}
        for file in os.listdir(self.ossa_folder):
            if file.endswith(".json"):
                try:
                    with open(os.path.join(self.ossa_folder, file), "r") as f:
                        ossa_entry = json.load(f)
                        severity = ossa_entry.get("severity", "Unknown")
                        title = ossa_entry.get("title", "Unknown Title")
                        ossa_id = ossa_entry.get("id", "Unknown ID")
                        
                        entry = {"severity": severity, "title": title, "id": ossa_id, "match_type": "direct"}
                        
                        for purl in ossa_entry.get("purls", []):
                            risk_data.setdefault(purl, []).append(entry)
                        for regex in ossa_entry.get("regex", []):
                            regex_entry = entry.copy()
                            regex_entry["match_type"] = "regex"
                            risk_data.setdefault(re.compile(regex), []).append(regex_entry)
                        for artifact in ossa_entry.get("artifacts", []):
                            for hash_type, hash_value in artifact.get("hashes", {}).items():
                                hash_entry = entry.copy()
                                hash_entry["match_type"] = "hash"
                                risk_data.setdefault(hash_value, []).append(hash_entry)
                except json.JSONDecodeError:
                    continue
        return risk_data

    def analyze(self, sbom_data):
        results = {}
        for component in sbom_data.get("components", []):
            purl = component.get("purl", "")
            component_hashes = self.extract_hashes(component)
            risk_entries = []
            seen_hashes = set()
            
            if purl in self.risk_data:
                risk_entries.extend(self.risk_data[purl])
                
            for regex_pattern, entries in self.risk_data.items():
                if isinstance(regex_pattern, re.Pattern) and regex_pattern.match(purl):
                    risk_entries.extend(entries)
                
            for hash_type, hash_value in component_hashes.items():
                if hash_value in self.risk_data and hash_value not in seen_hashes:
                    risk_entries.extend(self.risk_data[hash_value])
                    seen_hashes.add(hash_value)
            
            if self.min_severity:
                risk_entries = [entry for entry in risk_entries if self.severity_levels.get(entry["severity"], 0) >= self.severity_levels.get(self.min_severity, 0)]
            
            unique_risk_entries = []
            seen_entries = set()
            for entry in risk_entries:
                entry_key = (entry["severity"], entry["title"], entry["id"])
                if entry_key not in seen_entries:
                    unique_risk_entries.append(entry)
                    seen_entries.add(entry_key)
            
            if unique_risk_entries:
                results[component["name"]] = unique_risk_entries
        return results
