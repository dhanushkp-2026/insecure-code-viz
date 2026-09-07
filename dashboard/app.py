"""Streamlit dashboard for exploring Bandit security findings."""

from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

SEVERITY_COLOR_MAP = {
	"LOW": "#4C72B0",
	"MEDIUM": "#DD8452",
	"HIGH": "#C44E52",
}


def main() -> None:
	# Configure the browser tab and give the dashboard its main heading.
	st.set_page_config(
		page_title="Insecure Coding Pattern Dashboard",
		page_icon="🔍",
		layout="wide",
	)
	st.title("Insecure Coding Pattern Dashboard")
	st.caption(
		"Interactive analysis of Bandit security scan findings across open-source "
		"Python repositories"
	)

	# --- Load Data ---
	# Resolve the CSV relative to this file so the app works from the project
	# root as well as when started with ``streamlit run dashboard/app.py``.
	project_root = Path(__file__).resolve().parent.parent
	data_path = project_root / "data" / "processed" / "master.csv"
	findings_dataframe = pd.read_csv(data_path)

	# --- Sidebar Filters ---
	# Multiselect controls let users focus all metrics, charts, and rows on the
	# repositories and severity levels they want to investigate.
	repository_options = sorted(findings_dataframe["repo_name"].dropna().unique())
	severity_options = sorted(findings_dataframe["severity"].dropna().unique())
	confidence_options = sorted(findings_dataframe["confidence"].dropna().unique())
	selected_repositories = st.sidebar.multiselect(
		"repo_name",
		repository_options,
		default=repository_options,
	)
	selected_severities = st.sidebar.multiselect(
		"severity",
		severity_options,
		default=severity_options,
	)
	selected_confidences = st.sidebar.multiselect(
		"confidence",
		confidence_options,
		default=confidence_options,
	)

	# Apply every selected filter before calculating any displayed result.
	filtered_dataframe = findings_dataframe[
		findings_dataframe["repo_name"].isin(selected_repositories)
		& findings_dataframe["severity"].isin(selected_severities)
		& findings_dataframe["confidence"].isin(selected_confidences)
	]

	# --- Summary Metrics ---
	# These quick counts summarize exactly the filtered findings currently shown.
	total_findings = len(filtered_dataframe)
	number_of_repositories = filtered_dataframe["repo_name"].nunique()
	number_of_high_severity = filtered_dataframe["severity"].astype(str).str.upper().eq(
		"HIGH"
	).sum()
	metric_columns = st.columns(3)
	metric_columns[0].metric("Total Findings", total_findings)
	metric_columns[1].metric("Number of Repos Scanned", number_of_repositories)
	metric_columns[2].metric(
		"Number of High Severity Findings", number_of_high_severity
	)
	st.divider()

	# --- Charts ---
	# Each chart uses Plotly so it can be hovered, zoomed, and explored in place.
	chart_columns = st.columns(3)
	if filtered_dataframe.empty:
		st.info("No findings match the selected filters.")
	else:
		# The bar chart ranks the ten most common short pattern categories.
		top_patterns = filtered_dataframe["pattern_short"].value_counts().head(10)
		top_patterns = top_patterns.sort_values(ascending=True)
		top_patterns_figure = px.bar(
			x=top_patterns.values,
			y=top_patterns.index,
			orientation="h",
			labels={"x": "Findings", "y": "Pattern"},
			title="Top 10 Insecure Patterns",
		)
		chart_columns[0].plotly_chart(
			top_patterns_figure, use_container_width=True
		)

		# The donut chart shows how the filtered findings are divided by severity.
		severity_counts = filtered_dataframe["severity"].value_counts().reset_index()
		severity_counts.columns = ["severity", "findings"]
		severity_figure = px.pie(
			severity_counts,
			values="findings",
			names="severity",
			color="severity",
			color_discrete_map=SEVERITY_COLOR_MAP,
			hole=0.45,
			title="Severity Distribution",
		)
		chart_columns[1].plotly_chart(severity_figure, use_container_width=True)

		# The treemap sizes repository and severity sections by their finding count,
		# then shows which short patterns make up each severity section.
		treemap_data = (
			filtered_dataframe.groupby(
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
			title="Findings by Repository and Severity",
		)
		treemap_figure.update_traces(
			marker=dict(line=dict(color="white", width=2)),
			root_color="white",
		)
		treemap_figure.update_layout(paper_bgcolor="white")
		chart_columns[2].plotly_chart(treemap_figure, use_container_width=True)
	st.divider()

	# --- Findings Table ---
	# A fixed set of useful columns keeps the detailed results readable. The
	# height makes the table scrollable instead of pushing the whole page down.
	table_columns = [
		"repo_name",
		"file_path",
		"line_number",
		"pattern_short",
		"severity",
		"confidence",
	]
	st.dataframe(filtered_dataframe[table_columns], height=400, use_container_width=True)


if __name__ == "__main__":
	main()
