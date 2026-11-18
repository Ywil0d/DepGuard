
import pandas as pd
import streamlit as st

from core.github_analyzer import analyze_github_repository
from core.osv_scanner import scan_dependencies
from core.risk_analyzer import calculate_risk
from utils.helpers import parse_github_url


# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="DepGuard | Security Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)


# --------------------------------------------------
# CUSTOM CSS
# --------------------------------------------------

st.markdown(
    """
    <style>
        .stApp {
            background-color: #0b1120;
        }

        .block-container {
            max-width: 1150px;
            padding-top: 2.5rem;
            padding-bottom: 3rem;
        }

        .hero {
            padding: 2rem 0 1.5rem 0;
        }

        .hero-label {
            color: #38bdf8;
            font-size: 0.85rem;
            font-weight: 700;
            letter-spacing: 2px;
            text-transform: uppercase;
        }

        .hero-title {
            color: #f8fafc;
            font-size: 3rem;
            font-weight: 800;
            margin: 0.5rem 0;
        }

        .hero-description {
            color: #94a3b8;
            font-size: 1.05rem;
            max-width: 720px;
            line-height: 1.7;
        }

        .section-title {
            color: #f1f5f9;
            font-size: 1.35rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
        }

        .status-card {
            background: #111c30;
            border: 1px solid #24344d;
            border-radius: 12px;
            padding: 1rem 1.2rem;
            margin: 0.5rem 0 1rem 0;
        }

        .status-label {
            color: #94a3b8;
            font-size: 0.85rem;
        }

        .status-value {
            color: #f8fafc;
            font-size: 1.8rem;
            font-weight: 700;
        }

        div[data-testid="stMetric"] {
            background: #111c30;
            border: 1px solid #24344d;
            padding: 1rem;
            border-radius: 12px;
        }

        div.stButton > button[kind="primary"] {
            background: #0284c7;
            border: none;
            border-radius: 9px;
            min-height: 3rem;
            font-weight: 700;
        }

        div.stButton > button[kind="primary"]:hover {
            background: #0369a1;
        }

        .footer {
            color: #64748b;
            text-align: center;
            font-size: 0.85rem;
            padding-top: 2rem;
        }

        hr {
            border-color: #24344d;
        }
    </style>
    """,
    unsafe_allow_html=True,
)


# --------------------------------------------------
# SESSION STATE
# --------------------------------------------------

if "repository_data" not in st.session_state:
    st.session_state.repository_data = None

if "scan_results" not in st.session_state:
    st.session_state.scan_results = None


# --------------------------------------------------
# HEADER
# --------------------------------------------------

st.markdown(
    """
    <div class="hero">
        <div class="hero-label">Open Source Security Analysis</div>
        <div class="hero-title">🛡️ DepGuard</div>
        <div class="hero-description">
            Analyze GitHub repositories, discover vulnerable
            dependencies and understand your project's
            open-source security risks.
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)


# --------------------------------------------------
# REPOSITORY INPUT
# --------------------------------------------------

st.markdown(
    '<div class="section-title">Analyze a repository</div>',
    unsafe_allow_html=True,
)

st.write(
    "Enter a public GitHub repository URL to start scanning."
)

with st.form("repository_form"):
    repo_url = st.text_input(
        "GitHub Repository URL",
        value="",
        placeholder="https://github.com/psf/requests",
        help="Example: https://github.com/psf/requests",
    )

    submitted = st.form_submit_button(
        "🔍  Analyze Repository",
        type="primary",
        width="stretch",
    )


# --------------------------------------------------
# ANALYSIS PROCESS
# --------------------------------------------------

if submitted:

    # Clear previous results before a new analysis.
    st.session_state.repository_data = None
    st.session_state.scan_results = None

    if not repo_url.strip():
        st.error("Please enter a GitHub repository URL.")

    else:
        try:
            # Validate URL before making API requests.
            parse_github_url(repo_url)

            with st.status(
                "Analyzing repository...",
                expanded=True,
            ) as status:

                st.write("Connecting to GitHub...")

                repository_data = analyze_github_repository(
                    repo_url
                )

                st.write("Reading dependency files...")

                dependencies = repository_data["dependencies"]

                if not dependencies:
                    status.update(
                        label="No analyzable dependencies found.",
                        state="error",
                    )

                    st.session_state.repository_data = repository_data
                    st.session_state.scan_results = []

                else:
                    st.write(
                        f"Found {len(dependencies)} dependencies."
                    )

                    st.write("Querying OSV.dev vulnerability database...")

                    scan_results = scan_dependencies(dependencies)

                    st.session_state.repository_data = repository_data
                    st.session_state.scan_results = scan_results

                    failed_count = sum(
                        result["status"] == "Sorgulama başarısız"
                        for result in scan_results
                    )

                    if failed_count == len(scan_results):
                        status.update(
                            label="All vulnerability queries failed.",
                            state="error",
                        )
                    elif failed_count:
                        status.update(
                            label="Analysis completed with query errors.",
                            state="error",
                        )
                    else:
                        status.update(
                            label="Repository analysis completed.",
                            state="complete",
                        )

        except ValueError as error:
            st.error(str(error))

        except Exception as error:
            st.error(f"Analysis failed: {error}")


# --------------------------------------------------
# RESULTS
# --------------------------------------------------

repository_data = st.session_state.repository_data
scan_results = st.session_state.scan_results


if repository_data is not None and scan_results is not None:

    st.divider()

    st.markdown(
        '<div class="section-title">Repository Overview</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        f"**Repository:** "
        f"[{repository_data['owner']}/{repository_data['repo']}]"
        f"({repository_data['repository_url']})"
    )

    files_found = repository_data["files_found"]

    if files_found:
        st.caption(
            "Dependency files: " + ", ".join(files_found)
        )

    # ----------------------------------------------
    # RISK SUMMARY
    # ----------------------------------------------

    summary = calculate_risk(scan_results)

    st.divider()

    st.markdown(
        '<div class="section-title">Security Overview</div>',
        unsafe_allow_html=True,
    )

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Total Packages",
        summary["total_packages"],
    )

    col2.metric(
        "Vulnerable Packages",
        summary["vulnerable_packages"],
    )

    col3.metric(
        "Vulnerability Records",
        summary["total_vulnerabilities"],
    )
    risk_display = (
    f"{summary['risk_score']}/100"
    if summary["risk_score"] is not None
    else "N/A"
    )
    col4.metric(
        "DepGuard Risk Indicator",
        risk_display,
    )

    st.markdown(
        f"### Overall Assessment: {summary['risk_level']}"
    )

    st.caption(summary["risk_score_explanation"])

    # ----------------------------------------------
    # SCAN COMPLETENESS
    # ----------------------------------------------

    unresolved = summary["unresolved_packages"]
    failed = summary["failed_packages"]
    scanned = summary["scanned_packages"]

    if unresolved or failed:
        st.warning(
            f"Analysis is incomplete: {unresolved} package(s) "
            f"have unknown versions and {failed} package(s) "
            "could not be queried."
        )

    if scanned == 0:
        st.error(
            "No package could be successfully checked. "
            "A clean security result cannot be concluded."
        )

    elif summary["total_vulnerabilities"] == 0:
        if unresolved or failed:
            st.info(
                "No known vulnerabilities were returned for "
                "successfully queried versions. Some packages "
                "remain unverified."
            )
        else:
            st.success(
                "No known vulnerabilities were returned for "
                "the analyzed package versions."
            )

    else:
        st.error(
            f"{summary['total_vulnerabilities']} known "
            "vulnerability record(s) detected."
        )

    # ----------------------------------------------
    # SEVERITY CHART
    # ----------------------------------------------

    st.divider()

    st.markdown(
        '<div class="section-title">Vulnerability Severity</div>',
        unsafe_allow_html=True,
    )

    severity_counts = summary["severity_counts"]

    severity_df = pd.DataFrame(
        {
            "Severity": list(severity_counts.keys()),
            "Count": list(severity_counts.values()),
        }
    )

    severity_df = severity_df[
        severity_df["Count"] > 0
    ]

    if not severity_df.empty:
        st.bar_chart(
            severity_df.set_index("Severity"),
            y="Count",
        )
    else:
        st.info("No severity data is available.")

    # ----------------------------------------------
    # PACKAGE TABLE
    # ----------------------------------------------

    st.divider()

    st.markdown(
        '<div class="section-title">Package Analysis</div>',
        unsafe_allow_html=True,
    )

    package_rows = []

    for result in scan_results:
        package_rows.append(
            {
                "Package": result["package"],
                "Version": result["version"] or "Unknown",
                "Status": result["status"],
                "Vulnerabilities": len(
                    result["vulnerabilities"]
                ),
            }
        )

    package_df = pd.DataFrame(package_rows)

    st.dataframe(
        package_df,
        width="stretch",
        hide_index=True,
    )

    # CSV download
    st.download_button(
        "⬇️ Download Package Results (CSV)",
        data=package_df.to_csv(index=False).encode("utf-8-sig"),
        file_name="depguard_package_results.csv",
        mime="text/csv",
    )

    # ----------------------------------------------
    # VULNERABILITY DETAILS
    # ----------------------------------------------

    st.divider()

    st.markdown(
        '<div class="section-title">Vulnerability Details</div>',
        unsafe_allow_html=True,
    )

    vulnerability_rows = []

    for result in scan_results:

        for vulnerability in result["vulnerabilities"]:

            vulnerability_rows.append(
                {
                    "Package": result["package"],
                    "Version": result["version"],
                    "Vulnerability ID": vulnerability["id"],
                    "Summary": vulnerability["summary"],
                    "Severity": vulnerability["severity"],
                    "Fixed Versions": ", ".join(
                        vulnerability["fixed_versions"]
                    ) or "Not specified",
                    "OSV Details": vulnerability["details_url"],
                }
            )

    if vulnerability_rows:

        vulnerability_df = pd.DataFrame(
            vulnerability_rows
        )

        st.dataframe(
            vulnerability_df,
            width="stretch",
            hide_index=True,
            column_config={
                "OSV Details": st.column_config.LinkColumn(
                    "OSV Details",
                    display_text="Open advisory",
                )
            },
        )

        st.download_button(
            "⬇️ Download Vulnerability Report (CSV)",
            data=vulnerability_df.to_csv(
                index=False
            ).encode("utf-8-sig"),
            file_name="depguard_vulnerability_report.csv",
            mime="text/csv",
        )

    else:
        st.info(
            "No vulnerability details are available "
            "for the successfully queried versions."
        )

    # ----------------------------------------------
    # WARNINGS
    # ----------------------------------------------

    if repository_data["warnings"]:

        st.divider()

        st.markdown(
            '<div class="section-title">Repository Warnings</div>',
            unsafe_allow_html=True,
        )

        for warning in repository_data["warnings"]:
            st.warning(warning)


# --------------------------------------------------
# FOOTER
# --------------------------------------------------

st.divider()

st.markdown(
    """
    <div class="footer">
        DepGuard · Open Source Software Vulnerability Detection
        and Risk Analysis<br>
        Powered by Python, GitHub REST API and OSV.dev
    </div>
    """,
    unsafe_allow_html=True,
)
