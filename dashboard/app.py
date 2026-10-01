"""Interactive Streamlit dashboard for static-analysis findings."""

from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_PATH = PROJECT_ROOT / "data" / "processed" / "master.csv"

REQUIRED_COLUMNS = {
    "repo_name",
    "line_number",
    "pattern_type",
    "severity",
    "confidence",
    "scan_tool",
}
SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH"]
SEVERITY_COLOR_MAP = {
    "LOW": "#4C72B0",
    "MEDIUM": "#DD8452",
    "HIGH": "#C44E52",
}


@st.cache_data

def load_data(path: Path = DATA_PATH) -> pd.DataFrame:
    """Load the cleaned findings table once and validate its structure."""
    if not path.exists():
        raise FileNotFoundError(f"Findings file was not found: {path}")

    dataframe = pd.read_csv(path)
    missing_columns = sorted(REQUIRED_COLUMNS - set(dataframe.columns))
    if missing_columns:
        missing = ", ".join(missing_columns)
        raise ValueError(f"The findings file is missing required columns: {missing}")
    return dataframe


def apply_filters(
    dataframe: pd.DataFrame,
    repositories: list[str],
    severities: list[str],
    confidences: list[str],
    scan_tools: list[str],
) -> pd.DataFrame:
    """Return only findings matching all selected sidebar filters."""
    filtered = dataframe[
        dataframe["repo_name"].isin(repositories)
        & dataframe["severity"].isin(severities)
        & dataframe["confidence"].isin(confidences)
        & dataframe["scan_tool"].isin(scan_tools)
    ]
    return filtered.copy()


def show_metrics(dataframe: pd.DataFrame) -> None:
    """Display KPIs calculated from the currently filtered findings."""
    metric_columns = st.columns(4)
    metric_columns[0].metric("Total Findings", len(dataframe))
    metric_columns[1].metric("Repositories Represented", dataframe["repo_name"].nunique())
    metric_columns[2].metric(
        "High Severity Findings",
        int(dataframe["severity"].eq("HIGH").sum()),
    )
    pattern_column = "pattern_short" if "pattern_short" in dataframe.columns else "pattern_type"
    metric_columns[3].metric(
        "Unique Pattern Types",
        dataframe[pattern_column].nunique(dropna=True),
    )


def create_top_patterns_chart(dataframe: pd.DataFrame):
    """Create a horizontal bar chart for the ten most common patterns."""
    pattern_column = "pattern_short" if "pattern_short" in dataframe.columns else "pattern_type"
    counts = dataframe[pattern_column].fillna("<missing>").value_counts().head(10)
    counts = counts.sort_values(ascending=True)
    return px.bar(
        x=counts.values,
        y=counts.index,
        orientation="h",
        labels={"x": "Findings", "y": "Pattern type"},
        title="Top 10 Insecure Coding Patterns",
        color=counts.values,
        color_continuous_scale="Blues",
    ).update_layout(showlegend=False, coloraxis_showscale=False)


def create_severity_chart(dataframe: pd.DataFrame):
    """Create a pie chart from severity values actually present in the data."""
    severity_counts = dataframe["severity"].value_counts()
    severity_counts = severity_counts.reindex(
        [severity for severity in SEVERITY_ORDER if severity in severity_counts.index]
    ).dropna()
    return px.pie(
        values=severity_counts.values,
        names=severity_counts.index,
        hole=0.52,
        title="Severity Distribution",
        color=severity_counts.index,
        color_discrete_map=SEVERITY_COLOR_MAP,
    )


def create_heatmap(dataframe: pd.DataFrame):
    """Create a pattern-by-severity count heatmap for common patterns."""
    pattern_column = "pattern_short" if "pattern_short" in dataframe.columns else "pattern_type"
    top_patterns = dataframe[pattern_column].fillna("<missing>").value_counts().head(10).index
    heatmap_data = dataframe[dataframe[pattern_column].fillna("<missing>").isin(top_patterns)]
    severity_counts = pd.crosstab(
        heatmap_data[pattern_column].fillna("<missing>"),
        heatmap_data["severity"],
    )
    present_severities = [
        severity for severity in SEVERITY_ORDER if severity in severity_counts.columns
    ]
    severity_counts = severity_counts.reindex(
        index=top_patterns,
        columns=present_severities,
        fill_value=0,
    )
    return px.imshow(
        severity_counts,
        labels={"x": "Severity", "y": "Pattern type", "color": "Findings"},
        aspect="auto",
        title="Severity Distribution by Pattern Type",
        text_auto=True,
        color_continuous_scale="YlOrRd",
    )


def create_repository_chart(dataframe: pd.DataFrame):
    """Create a treemap grouping findings by repository and severity."""
    treemap_data = (
        dataframe.groupby(["repo_name", "severity"], dropna=False)
        .size()
        .reset_index(name="findings")
    )
    return px.treemap(
        treemap_data,
        path=["repo_name", "severity"],
        values="findings",
        color="severity",
        color_discrete_map=SEVERITY_COLOR_MAP,
        labels={"findings": "Findings", "repo_name": "Repository"},
        title="Findings by Repository and Severity",
    )


def show_findings_table(dataframe: pd.DataFrame) -> None:
    """Display the filtered individual findings using available columns."""
    st.subheader("Detailed Findings")
    table_columns = [
        "repo_name",
        "file_path",
        "line_number",
        "pattern_short",
        "pattern_type",
        "severity",
        "confidence",
        "scan_tool",
    ]
    available_columns = [column for column in table_columns if column in dataframe.columns]
    st.dataframe(dataframe[available_columns], width="stretch", hide_index=True)


def show_sidebar_filters(dataframe: pd.DataFrame) -> dict[str, list[str]]:
    """Build dynamic multiselect filters whose defaults include every value."""
    with st.sidebar:
        st.header("Filters")
        return {
            "repositories": st.multiselect(
                "Repository",
                sorted(dataframe["repo_name"].dropna().unique()),
                default=sorted(dataframe["repo_name"].dropna().unique()),
            ),
            "severities": st.multiselect(
                "Severity",
                sorted(dataframe["severity"].dropna().unique()),
                default=sorted(dataframe["severity"].dropna().unique()),
            ),
            "confidences": st.multiselect(
                "Confidence",
                sorted(dataframe["confidence"].dropna().unique()),
                default=sorted(dataframe["confidence"].dropna().unique()),
            ),
            "scan_tools": st.multiselect(
                "Scan Tool",
                sorted(dataframe["scan_tool"].dropna().unique()),
                default=sorted(dataframe["scan_tool"].dropna().unique()),
            ),
        }


def main() -> None:
    """Render the dashboard."""
    st.set_page_config(page_title="Insecure Coding Pattern Dashboard", layout="wide")
    st.title("Insecure Coding Pattern Dashboard")
    st.write("Interactive visualization of static-analysis findings across open-source repositories.")
    st.info(
        "Static-analysis findings are potential insecure coding patterns and should not be "
        "interpreted as confirmed exploitable vulnerabilities."
    )

    try:
        dataframe = load_data()
    except FileNotFoundError as error:
        st.error(str(error))
        st.stop()
    except (pd.errors.EmptyDataError, ValueError) as error:
        st.error(f"Unable to load findings data: {error}")
        st.stop()

    if dataframe.empty:
        st.warning("The findings CSV is empty. Run the data pipeline before opening the dashboard.")
        st.stop()

    filters = show_sidebar_filters(dataframe)
    filtered = apply_filters(dataframe, **filters)
    show_metrics(filtered)

    if filtered.empty:
        st.warning("No findings match the selected filters.")
        st.stop()

    st.subheader("Visual Overview")
    top_patterns_column, severity_column = st.columns(2)
    with top_patterns_column:
        st.plotly_chart(create_top_patterns_chart(filtered), width="stretch")
    with severity_column:
        st.plotly_chart(create_severity_chart(filtered), width="stretch")

    st.plotly_chart(create_heatmap(filtered), width="stretch")
    st.plotly_chart(create_repository_chart(filtered), width="stretch")
    show_findings_table(filtered)


if __name__ == "__main__":
    main()
