"""Run Bandit and Semgrep against every cloned repository."""

from pathlib import Path
import subprocess


def scan_repositories() -> tuple[int, list[str], int, list[str]]:
	"""Return Bandit and Semgrep success counts and failure lists."""
	# Build paths from this file so the script works even when launched from
	# a different current directory, such as with ``python scripts/scan_repos.py``.
	project_root = Path(__file__).resolve().parent.parent
	repos_directory = project_root / "repos"
	raw_data_directory = project_root / "data" / "raw"

	raw_data_directory.mkdir(parents=True, exist_ok=True)

	bandit_failures: list[str] = []
	semgrep_failures: list[str] = []
	bandit_successes = 0
	semgrep_successes = 0

	# Each direct child directory represents one cloned GitHub repository.
	repositories = sorted(
		(path for path in repos_directory.iterdir() if path.is_dir()),
		key=lambda path: path.name.lower(),
	) if repos_directory.exists() else []

	for repository_path in repositories:
		repository_name = repository_path.name
		bandit_output_path = raw_data_directory / f"{repository_name}_bandit.json"
		print(f"Scanning {repository_name} with Bandit...", flush=True)

		try:
			bandit_result = subprocess.run(
				[
					"bandit",
					"-r",
					str(repository_path),
					"-f",
					"json",
					"-o",
					str(bandit_output_path),
				],
				check=False,
			)
		except OSError as error:
			print(f"Warning: could not run Bandit for {repository_name}: {error}")
			bandit_failures.append(repository_name)
		else:
			# Bandit returns 1 when it found findings; that is still successful.
			if bandit_result.returncode not in (0, 1):
				print(
					f"Warning: Bandit failed for {repository_name} "
					f"(exit code {bandit_result.returncode})"
				)
				bandit_failures.append(repository_name)
			else:
				bandit_successes += 1
				print("Bandit scan completed.")

		semgrep_output_path = raw_data_directory / f"{repository_name}_semgrep.json"
		print(f"\nScanning {repository_name} with Semgrep...", flush=True)
		try:
			semgrep_result = subprocess.run(
    [
        "semgrep",
        "scan",
        "--config=auto",
        "--no-git-ignore",
        "--json",
        "--output",
        str(semgrep_output_path),
        str(repository_path),
    ],
    check=False,
)
		except OSError as error:
			print(f"Warning: could not run Semgrep for {repository_name}: {error}")
			semgrep_failures.append(repository_name)
		else:
			if semgrep_result.returncode != 0:
				print(
					f"Warning: Semgrep failed for {repository_name} "
					f"(exit code {semgrep_result.returncode})"
				)
				semgrep_failures.append(repository_name)
			else:
				semgrep_successes += 1
				print("Semgrep scan completed.")

	print("\nScan summary:")
	print(f"Repositories scanned: {len(repositories)}")
	print(f"Bandit successes/failures: {bandit_successes}/{len(bandit_failures)}")
	print(f"Semgrep successes/failures: {semgrep_successes}/{len(semgrep_failures)}")
	print(
		"Bandit failed repositories: "
		+ (", ".join(bandit_failures) if bandit_failures else "none")
	)
	print(
		"Semgrep failed repositories: "
		+ (", ".join(semgrep_failures) if semgrep_failures else "none")
	)

	return (
		bandit_successes,
		bandit_failures,
		semgrep_successes,
		semgrep_failures,
	)


if __name__ == "__main__":
	scan_repositories()
