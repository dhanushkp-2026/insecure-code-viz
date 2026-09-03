"""Combine Bandit JSON reports into one CSV file for the dashboard."""

import json
from pathlib import Path

import pandas as pd


def shorten_pattern(text: str) -> str:
	"""Turn long Bandit descriptions into short, readable chart labels."""
	# Bandit's descriptions are written for detailed reports. These labels make
	# the same findings easier to read in chart axes and category names.
	text_lower = text.lower()
	if "hardcoded password" in text_lower:
		return "Hardcoded Password"
	if "assert" in text_lower:
		return "Assert Usage"
	if "without a shell" in text_lower:
		return "Subprocess Without Shell"
	if "partial executable path" in text_lower:
		return "Partial Executable Path"
	if "subprocess" in text_lower:
		return "Subprocess Risk"
	if "timeout" in text_lower:
		return "Missing Request Timeout"
	if "pickle" in text_lower:
		return "Insecure Deserialization (Pickle)"
	if "xss" in text_lower or "markup" in text_lower:
		return "Potential XSS"
	if "random" in text_lower:
		return "Weak Random Generator"
	if "temp file" in text_lower or "tmp" in text_lower:
		return "Insecure Temp File Usage"
	if "debug=True".lower() in text_lower or "debug" in text_lower:
		return "Debug Mode Enabled"
	return f"{text[:40]}..."


def parse_bandit_results() -> pd.DataFrame:
	"""Read all raw Bandit reports and return their findings as a DataFrame."""
	# Resolve paths from this script so direct execution works from any folder.
	project_root = Path(__file__).resolve().parent.parent
	raw_data_directory = project_root / "data" / "raw"
	processed_data_directory = project_root / "data" / "processed"
	processed_data_directory.mkdir(parents=True, exist_ok=True)

	# Defining the columns up front keeps the CSV consistent, even when there
	# are no findings in any report.
	columns = [
		"repo_name",
		"language",
		"file_path",
		"line_number",
		"pattern_type",
		"pattern_short",
		"severity",
		"confidence",
		"scan_tool",
	]
	rows: list[dict[str, object]] = []
	findings_per_repo: dict[str, int] = {}

	# Every matching JSON file is one Bandit report for one cloned repository.
	report_files = sorted(raw_data_directory.glob("*_bandit.json"))
	for report_path in report_files:
		# Remove the known suffix to get the repository name, for example
		# ``flask_bandit.json`` becomes ``flask``.
		repo_name = report_path.name[: -len("_bandit.json")]

		# Bandit's JSON contains metadata plus a ``results`` list. Each item
		# in that list describes one insecure coding pattern it detected.
		with report_path.open("r", encoding="utf-8") as report_file:
			report_data = json.load(report_file)
		findings = report_data.get("results", [])

		findings_per_repo[repo_name] = len(findings)
		for finding in findings:
			pattern_type = finding.get("issue_text", "")
			rows.append(
				{
					"repo_name": repo_name,
					"language": "Python",
					"file_path": finding.get("filename"),
					"line_number": finding.get("line_number"),
					"pattern_type": pattern_type,
					"pattern_short": shorten_pattern(pattern_type),
					"severity": finding.get("issue_severity"),
					"confidence": finding.get("issue_confidence"),
					"scan_tool": "Bandit",
				}
			)

		# A report with no results is valid: it simply means Bandit found no
		# matching patterns in that repository.
		print(f"{repo_name}: {len(findings)} findings")

	# Pandas turns the list of dictionaries into a table with named columns.
	findings_dataframe = pd.DataFrame(rows, columns=columns)
	output_path = processed_data_directory / "master.csv"
	findings_dataframe.to_csv(output_path, index=False)

	print(f"Total findings extracted: {len(findings_dataframe)}")
	print("Findings per repo:")
	for repo_name, finding_count in findings_per_repo.items():
		print(f"- {repo_name}: {finding_count}")

	return findings_dataframe


if __name__ == "__main__":
	parse_bandit_results()
