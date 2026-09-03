"""Run Bandit against every cloned repository in the repos directory."""

from pathlib import Path
import subprocess


def scan_repositories() -> tuple[int, list[str]]:
	"""Scan each repository and return the success count and failed names."""
	# Build paths from this file so the script works even when launched from
	# a different current directory, such as with ``python scripts/scan_repos.py``.
	project_root = Path(__file__).resolve().parent.parent
	repos_directory = project_root / "repos"
	raw_data_directory = project_root / "data" / "raw"

	# Bandit is a Python security scanner. It examines source code for common
	# risky patterns, then writes its findings as machine-readable JSON.
	raw_data_directory.mkdir(parents=True, exist_ok=True)

	failed_repositories: list[str] = []
	successful_scans = 0

	# Each direct child directory represents one cloned GitHub repository.
	repositories = sorted(
		(path for path in repos_directory.iterdir() if path.is_dir()),
		key=lambda path: path.name.lower(),
	) if repos_directory.exists() else []

	for repository_path in repositories:
		repository_name = repository_path.name
		output_path = raw_data_directory / f"{repository_name}_bandit.json"
		print(f"Scanning {repository_name}...", flush=True)

		try:
			# -r means recursive scanning, and -f json makes the report easy
			# for the later parsing script to process.
			result = subprocess.run(
				[
					"bandit",
					"-r",
					str(repository_path),
					"-f",
					"json",
					"-o",
					str(output_path),
				],
				check=False,
			)
		except OSError as error:
			print(f"Warning: could not run Bandit for {repository_name}: {error}")
			failed_repositories.append(repository_name)
			continue

		# Bandit returns 1 when it found security issues. That is a useful,
		# expected result; any other non-zero code means the scan failed.
		if result.returncode not in (0, 1):
			print(
				f"Warning: Bandit failed for {repository_name} "
				f"(exit code {result.returncode})"
			)
			failed_repositories.append(repository_name)
			continue

		successful_scans += 1
		print(f"Done: {repository_name} -> {output_path.relative_to(project_root)}")

	print(f"\nSuccessfully scanned: {successful_scans} repo(s)")
	if failed_repositories:
		print("Failed repositories: " + ", ".join(failed_repositories))
	else:
		print("Failed repositories: none")

	return successful_scans, failed_repositories


if __name__ == "__main__":
	scan_repositories()
