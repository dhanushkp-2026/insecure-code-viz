"""Safely clean the combined security findings used by the dashboard."""

from pathlib import Path
import shutil
import sys

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parent.parent
MASTER_PATH = PROJECT_ROOT / "data" / "processed" / "master.csv"
BACKUP_PATH = PROJECT_ROOT / "data" / "processed" / "master_before_cleaning.csv"

REQUIRED_COLUMNS = {
	"repo_name",
	"language",
	"file_path",
	"line_number",
	"pattern_type",
	"severity",
	"confidence",
	"scan_tool",
}


def load_data(path: Path = MASTER_PATH) -> pd.DataFrame:
	"""Load the processed findings table from the project data directory."""
	return pd.read_csv(path, keep_default_na=True)


def validate_columns(dataframe: pd.DataFrame) -> None:
	"""Fail early when the parser output is missing a required field."""
	missing_columns = sorted(REQUIRED_COLUMNS - set(dataframe.columns))
	if missing_columns:
		missing = ", ".join(missing_columns)
		raise ValueError(f"master.csv is missing required columns: {missing}")


def _shorten_pattern(pattern_type: object) -> object:
	"""Reuse parse_results.py's labels when a short label is needed."""
	if pd.isna(pattern_type) or not str(pattern_type).strip():
		return pd.NA

	scripts_directory = str(Path(__file__).resolve().parent)
	if scripts_directory not in sys.path:
		sys.path.insert(0, scripts_directory)
	from parse_results import shorten_pattern

	return shorten_pattern(str(pattern_type).strip())


def _normalize_scan_tool(value: object) -> object:
	"""Keep scanner names consistent without changing unknown tool names."""
	if pd.isna(value):
		return pd.NA

	normalized = " ".join(str(value).split())
	known_names = {"bandit": "Bandit", "semgrep": "Semgrep"}
	return known_names.get(normalized.casefold(), normalized)


def clean_data(dataframe: pd.DataFrame) -> pd.DataFrame:
	"""Apply conservative cleanup while retaining the original findings."""
	# Cleaning makes charts reliable by removing formatting noise, not by
	# changing what a scanner reported or inventing vulnerability scores.
	cleaned = dataframe.copy()

	# Completely empty rows contain no security finding information.
	cleaned = cleaned.dropna(how="all")

	# Whitespace around text can create duplicate-looking categories.
	string_columns = cleaned.select_dtypes(include=["object", "string"]).columns
	for column in string_columns:
		cleaned[column] = cleaned[column].map(
			lambda value: " ".join(value.split()) if isinstance(value, str) else value
		)

	# An absent short label is derived from the same logic used by the parser.
	if "pattern_short" not in cleaned.columns:
		cleaned["pattern_short"] = cleaned["pattern_type"].map(_shorten_pattern)
	else:
		missing_short_labels = cleaned["pattern_short"].isna() | cleaned["pattern_short"].eq("")
		cleaned.loc[missing_short_labels, "pattern_short"] = cleaned.loc[
			missing_short_labels, "pattern_type"
		].map(_shorten_pattern)

	# Severity and confidence are categories from the scanner, so only their
	# presentation is normalized; LOW findings remain valid findings.
	for column in ("severity", "confidence"):
		cleaned[column] = cleaned[column].map(
			lambda value: value.upper() if isinstance(value, str) else value
		)

	cleaned["scan_tool"] = cleaned["scan_tool"].map(_normalize_scan_tool)
	cleaned["line_number"] = pd.to_numeric(cleaned["line_number"], errors="coerce").astype("Int64")

	# Exact duplicate rows are repeated copies of the same finding.
	cleaned = cleaned.drop_duplicates()
	return cleaned.reset_index(drop=True)


def print_summary(
	rows_before: int, cleaned: pd.DataFrame, duplicates_removed: int
) -> None:
	"""Print useful checks for the person running the cleaning stage."""
	print(f"Rows before cleaning: {rows_before}")
	print(f"Rows after cleaning: {len(cleaned)}")
	print(f"Duplicates removed: {duplicates_removed}")
	print("Missing values by column:")
	for column, count in cleaned.isna().sum().items():
		print(f"- {column}: {count}")
	print(f"Number of repositories: {cleaned['repo_name'].nunique(dropna=True)}")
	for column, heading in (
		("severity", "Findings by severity"),
		("confidence", "Findings by confidence"),
		("scan_tool", "Findings by scan tool"),
	):
		print(f"{heading}:")
		counts = cleaned[column].fillna("<missing>").value_counts().sort_index()
		for value, count in counts.items():
			print(f"- {value}: {count}")


def save_data(cleaned: pd.DataFrame, path: Path = MASTER_PATH) -> None:
	"""Back up the original once, then save the cleaned table."""
	# Keep the first pre-cleaning file so repeated runs do not erase the
	# original reference data.
	if not BACKUP_PATH.exists():
		shutil.copy2(path, BACKUP_PATH)
	cleaned.to_csv(path, index=False)


def main() -> None:
	"""Run the complete data-cleaning stage."""
	dataframe = load_data()
	validate_columns(dataframe)
	rows_before = len(dataframe)
	non_empty_rows = dataframe.dropna(how="all")
	duplicate_rows = len(non_empty_rows) - len(non_empty_rows.drop_duplicates())
	cleaned = clean_data(dataframe)
	print_summary(rows_before, cleaned, duplicate_rows)
	save_data(cleaned)
	print(f"Saved cleaned data to: {MASTER_PATH}")


if __name__ == "__main__":
	main()
