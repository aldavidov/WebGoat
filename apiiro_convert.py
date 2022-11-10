import json
from datetime import datetime
import argparse
import re

SEMGREP_OUTPUT_PARAM_NAME = 'semgrep_output_file'
FINDINGS_REPORT_PARAM_NAME = 'findings_report_output_file'
RESULTS_KEY = "results"

SEMGREP_SEVERITY_TO_INT = {
    "INFO": 0,
    "WARNING": 2,
    "ERROR": 4
}


def should_convert_semgrep_finding_json(semgrep_finding_json):
    return semgrep_finding_json.get("extra", dict()).get("metadata", dict()).get("category", "") == "security"


def _cwe_name_to_type(cwe_name):
    if cwe_name is None:
        return ""
    match = re.match("CWE-[0-9]+: ", cwe_name)
    if match is None:
        return cwe_name
    span = match.span()
    if span[0] != 0:
        return cwe_name
    return cwe_name[span[1]:]


def finding_from_semgrep_finding_json(semgrep_finding_json):
    extra_fields = semgrep_finding_json.get("extra", dict())
    metadata_fields = extra_fields.get("metadata", dict())
    return {
        "FilePath": semgrep_finding_json.get("path"),
        "LineNumber": semgrep_finding_json.get("start", dict()).get("line", None),
        "EndLineNumber": semgrep_finding_json.get("end", dict()).get("line", None),
        "Type": _cwe_name_to_type(metadata_fields.get("cwe")),
        "CweIdentifiers": [metadata_fields.get("cwe")],
        "Severity": SEMGREP_SEVERITY_TO_INT.get(extra_fields.get("severity", 0)),
        "Description": extra_fields.get("message"),
        "standards": ["OWASP"] if "owasp" in metadata_fields else [],
        "Tags": {
            "CheckId": semgrep_finding_json.get("check_id"),
        }
    }


def create_findings_report():
    return {
        "ScanType": "SAST",
        "Provider": "Semgrep",
        "Time": datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f%z')
    }


def semgrep_output_to_findings_report(input_file, output_file):
    with open(input_file, "r") as f:
        data = json.load(f)
    if RESULTS_KEY not in data:
        raise Exception(f"JSON file does not have a \"{RESULTS_KEY}\" key")
    results = data[RESULTS_KEY]
    findings_report = create_findings_report()
    findings_report["CodeFindings"] = [finding_from_semgrep_finding_json(result) for result in results if
                                   should_convert_semgrep_finding_json(result)]
    with open(output_file, "w") as f:
        json.dump(findings_report, f)


def main():
    parser = argparse.ArgumentParser(description='Convert Semgrep output to Apiiro Findings Report format.')
    parser.add_argument(SEMGREP_OUTPUT_PARAM_NAME, type=str)
    parser.add_argument(FINDINGS_REPORT_PARAM_NAME, type=str)
    args = vars(parser.parse_args())
    semgrep_output_to_findings_report(args[SEMGREP_OUTPUT_PARAM_NAME], args[FINDINGS_REPORT_PARAM_NAME])


if __name__ == '__main__':
    main()
