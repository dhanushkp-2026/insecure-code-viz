"""Combine Bandit and Semgrep JSON reports into one CSV file."""

import json
from pathlib import Path
import re

import pandas as pd


COLUMNS = [
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


def shorten_semgrep_pattern(check_id: object) -> str:
	"""Turn a Semgrep rule id into a concise readable category."""
	text = str(check_id or "Unknown Semgrep Rule")
	normalized = re.sub(r"[._\-/:]+", " ", text)
	normalized = re.sub(r"(?<=[a-z])(?=[A-Z])", " ", normalized)
	normalized = " ".join(normalized.lower().split())

	if "mutable action tag" in normalized:
		return "Mutable GitHub Action Tag"
	if "no csrf token" in normalized:
		return "Django No CSRF Token"
	if "sha1" in normalized or "insecure hash algorithm sha1" in normalized:
		return "SHA1 Usage"
	if "sha256" in normalized:
		return "SHA256 Usage"
	if "missing integrity" in normalized:
		return "Missing Integrity Attribute"
	if "non literal import" in normalized:
		return "Non-Literal Import"
	if "eval detected" in normalized or re.search(r"\beval\b", normalized):
		return "Eval Usage"
	if "exec detected" in normalized or re.search(r"\bexec\b", normalized):
		return "Exec Usage"
	if "explicit unsafe with markup" in normalized or "unsafe markup" in normalized:
		return "Unsafe Markup"
	if "dependabot missing cooldown" in normalized:
		return "Dependabot Missing Cooldown"

	if " security " in f" {normalized} ":
		normalized = normalized.rsplit(" security ", 1)[-1]
	words = normalized.split()
	words = [word for index, word in enumerate(words) if index == 0 or word != words[index - 1]]
	for phrase_length in range(len(words) // 2, 0, -1):
		for start in range(len(words) - (phrase_length * 2) + 1):
			first = words[start : start + phrase_length]
			second_start = start + phrase_length
			second = words[second_start : second_start + phrase_length]
			if first == second:
				words = words[:second_start] + words[second_start + phrase_length :]
				break
		else:
			continue
		break

	label = " ".join(words).title().strip()
	return (label or "Unknown Semgrep Rule")[:45].rstrip()


def infer_semgrep_language(result: dict[str, object], file_path: object) -> str:
	"""Infer a source language from Semgrep metadata or the file suffix."""
	extra = result.get("extra")
	metadata = extra.get("metadata", {}) if isinstance(extra, dict) else {}
	language_names = {
		"python": "Python",
		"javascript": "JavaScript",
		"typescript": "TypeScript",
		"java": "Java",
		"go": "Go",
		"ruby": "Ruby",
		"php": "PHP",
		"c": "C",
		"cpp": "C++",
		"c++": "C++",
	}
	for source in (result, extra, metadata):
		if isinstance(source, dict):
			language_values = source.get("languages", source.get("language"))
			if isinstance(language_values, str):
				language_values = [language_values]
			if isinstance(language_values, list):
				for language in language_values:
					if isinstance(language, str) and language.strip():
						language_key = language.strip().lower()
						return language_names.get(language_key, language.strip())

	extension_languages = {
		".py": "Python",
		".js": "JavaScript",
		".ts": "TypeScript",
		".java": "Java",
		".c": "C",
		".cpp": "C++",
		".cc": "C++",
		".cxx": "C++",
		".go": "Go",
		".rb": "Ruby",
		".php": "PHP",
	}
	return extension_languages.get(Path(str(file_path or "")).suffix.lower(), "Unknown")


def parse_semgrep_finding(repo_name: str, finding: object) -> dict[str, object] | None:
	"""Map one Semgrep result into the dashboard's common schema."""
	if not isinstance(finding, dict):
		return None
	extra = finding.get("extra")
	extra = extra if isinstance(extra, dict) else {}
	metadata = extra.get("metadata")
	metadata = metadata if isinstance(metadata, dict) else {}
	file_path = finding.get("path")
	pattern_type = extra.get("message") or finding.get("check_id") or ""
	severity = str(extra.get("severity") or "UNKNOWN").upper()
	severity = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}.get(
		severity, severity
	)
	confidence_value = metadata.get("confidence")
	if isinstance(confidence_value, (str, int, float)) and not isinstance(
		confidence_value, bool
	):
		confidence = str(confidence_value).strip().upper() or "UNKNOWN"
	else:
		confidence = "UNKNOWN"
	start = finding.get("start")
	return {
		"repo_name": repo_name,
		"language": infer_semgrep_language(finding, file_path),
		"file_path": file_path,
		"line_number": start.get("line") if isinstance(start, dict) else None,
		"pattern_type": pattern_type,
		"pattern_short": shorten_semgrep_pattern(finding.get("check_id")),
		"severity": severity,
		"confidence": confidence,
		"scan_tool": "Semgrep",
	}


def parse_results() -> pd.DataFrame:
	"""Read all raw scanner reports and return their findings as a DataFrame."""
	# Resolve paths from this script so direct execution works from any folder.
	project_root = Path(__file__).resolve().parent.parent
	raw_data_directory = project_root / "data" / "raw"
	processed_data_directory = project_root / "data" / "processed"
	processed_data_directory.mkdir(parents=True, exist_ok=True)

	# Defining the columns up front keeps the CSV consistent, even when there
	# are no findings in any report.
	rows: list[dict[str, object]] = []
	findings_per_repo: dict[str, int] = {}
	findings_per_scanner = {"Bandit": 0, "Semgrep": 0}

	report_files = sorted(
		list(raw_data_directory.glob("*_bandit.json"))
		+ list(raw_data_directory.glob("*_semgrep.json"))
	)
	for report_path in report_files:
		suffix = "_bandit.json" if report_path.name.endswith("_bandit.json") else "_semgrep.json"
		repo_name = report_path.name[: -len(suffix)]
		print(f"Reading report: {report_path.name}")
		try:
			try:
				with report_path.open("r", encoding="utf-8") as report_file:
					report_data = json.load(report_file)
			except UnicodeDecodeError:
				try:
					with report_path.open("r", encoding="cp1252") as report_file:
						report_data = json.load(report_file)
					print(
						f"Warning: {report_path.name} was not UTF-8; "
						"decoded using cp1252 fallback."
					)
				except UnicodeDecodeError as error:
					print(
						f"Warning: skipping report {report_path.name}; "
						f"UTF-8 and cp1252 decoding failed: {error}"
					)
					continue
				except (OSError, json.JSONDecodeError) as error:
					print(f"Warning: skipping malformed report {report_path.name}: {error}")
					continue
		except (OSError, json.JSONDecodeError) as error:
			print(f"Warning: skipping malformed report {report_path.name}: {error}")
			continue
		if not isinstance(report_data, dict) or not isinstance(report_data.get("results"), list):
			print(f"Warning: skipping report without a results list: {report_path.name}")
			continue

		findings = report_data["results"]
		scanner = "Bandit" if suffix == "_bandit.json" else "Semgrep"
		parsed_count = 0
		for finding in findings:
			if scanner == "Bandit":
				if not isinstance(finding, dict):
					continue
				pattern_type = str(finding.get("issue_text") or "")
				row = {
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
			else:
				row = parse_semgrep_finding(repo_name, finding)
				if row is None:
					continue
			rows.append(row)
			parsed_count += 1

		findings_per_repo[repo_name] = findings_per_repo.get(repo_name, 0) + parsed_count
		findings_per_scanner[scanner] += parsed_count

		# A report with no results is valid: it simply means Bandit found no
		# matching patterns in that repository.
		print(f"{repo_name} [{scanner}]: {len(findings)} findings")

	# Pandas turns the list of dictionaries into a table with named columns.
	findings_dataframe = pd.DataFrame(rows, columns=COLUMNS)
	output_path = processed_data_directory / "master.csv"
	findings_dataframe.to_csv(output_path, index=False)

	print(f"Total findings: {len(findings_dataframe)}")
	print(f"Bandit findings: {findings_per_scanner['Bandit']}")
	print(f"Semgrep findings: {findings_per_scanner['Semgrep']}")
	print("Findings by repository:")
	for repo_name, finding_count in findings_per_repo.items():
		print(f"- {repo_name}: {finding_count}")
	print("Findings by severity:")
	for severity, count in findings_dataframe["severity"].value_counts(dropna=False).items():
		print(f"- {severity}: {count}")
	print("Findings by scanner:")
	for scanner, count in findings_dataframe["scan_tool"].value_counts(dropna=False).items():
		print(f"- {scanner}: {count}")

	return findings_dataframe


if __name__ == "__main__":
	parse_results()
