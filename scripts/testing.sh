#!/bin/bash
python3 -m unittest discover tests
ossbomer-oslc --file tests/test_sbom.json --use-case distribution --min-severity Medium --json-output