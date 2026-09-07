"""Create interactive Plotly charts from the combined Bandit findings."""

from pathlib import Path

import pandas as pd
import plotly.express as px

SEVERITY_COLOR_MAP = {
	"LOW": "#4C72B0",
	"MEDIUM": "#DD8452",
	"HIGH": "#C44E52",
}


def make_charts() -> None:
	"""Load the master findings file and save three interactive charts."""
	# Resolve paths from this script so the direct command works from any folder.
	project_root = Path(__file__).resolve().parent.parent
	input_path = project_root / "data" / "processed" / "master.csv"
	charts_directory = project_root / "charts"
	charts_directory.mkdir(parents=True, exist_ok=True)

	# Pandas loads the CSV into a table that Plotly can use to build charts.
	findings_dataframe = pd.read_csv(input_path)

	# This bar chart highlights the 15 patterns that appear most often across
	# all repositories, making the most common security concerns easy to compare.
	top_patterns = findings_dataframe["pattern_short"].value_counts().head(15)
	top_patterns = top_patterns.sort_values(ascending=True)
	top_patterns_figure = px.bar(
		x=top_patterns.values,
		y=top_patterns.index,
		orientation="h",
		labels={"x": "Findings", "y": "Pattern type"},
		title="Most Frequent Insecure Coding Patterns",
	)
	top_patterns_figure.write_html(charts_directory / "top_patterns.html")
	top_patterns_figure.show()

	# A heatmap uses color intensity to show how often each of the 10 most
	# common patterns occurs at each severity level.
	top_ten_patterns = findings_dataframe["pattern_short"].value_counts().head(10).index
	heatmap_data = findings_dataframe[
		findings_dataframe["pattern_short"].isin(top_ten_patterns)
	]
	severity_counts = pd.crosstab(
		heatmap_data["pattern_short"],
		heatmap_data["severity"],
	).reindex(top_ten_patterns, fill_value=0)
	severity_heatmap_figure = px.imshow(
		severity_counts,
		labels={"x": "Severity", "y": "Pattern type", "color": "Findings"},
		 aspect="auto",
		title="Severity Distribution by Pattern Type",
		text_auto=True,
	)
	severity_heatmap_figure.write_html(charts_directory / "severity_heatmap.html")
	severity_heatmap_figure.show()

	# The treemap gives each repository a rectangle whose size represents its
	# finding count, with each repository divided into severity categories.
	treemap_data = (
		findings_dataframe.groupby(
			["repo_name", "severity", "pattern_short"], dropna=False
		)
		.size()
		.reset_index(name="findings")
	)
	treemap_figure = px.treemap(
		treemap_data,
		path=["repo_name", "severity", "pattern_short"],
		values="findings",
		color="severity",
		color_discrete_map=SEVERITY_COLOR_MAP,
		labels={"findings": "Findings", "repo_name": "Repository"},
		title="Findings by Repository and Severity",
	)
	treemap_figure.write_html(charts_directory / "repo_treemap.html")
	treemap_figure.show()


if __name__ == "__main__":
	make_charts()