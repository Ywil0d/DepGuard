import pandas as pd
import streamlit as st

from core.github_analyzer import analyze_github_repository
from core.osv_scanner import scan_dependencies
from core.risk_analyzer import calculate_risk


st.set_page_config(
    page_title="DepGuard | Security Analyzer",
    page_icon="🛡️",
    layout="wide",
)


def show_results(repository_data: dict, scan_results: list[dict]):
    """
    Analiz sonuçlarını Streamlit arayüzünde gösterir.
    """

    summary = calculate_risk(scan_results)

    st.divider()
    st.subheader("Repository Bilgileri")

    st.markdown(
        f"**Depo:** [{repository_data['owner']}/"
        f"{repository_data['repo']}]"
        f"({repository_data['repository_url']})"
    )

    st.write(
        "Okunan dosyalar:",
        ", ".join(repository_data["files_found"]),
    )

    # Özet metrikler
    st.divider()
    st.subheader("Güvenlik Analizi Özeti")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Toplam paket",
        summary["total_packages"],
    )

    col2.metric(
        "Açık bulunan paket",
        summary["vulnerable_packages"],
    )

    col3.metric(
        "Güvenlik açığı kaydı",
        summary["total_vulnerabilities"],
    )

    col4.metric(
        "Risk göstergesi",
        f"{summary['risk_score']}/100",
    )

    st.write(f"**Genel değerlendirme:** {summary['risk_level']}")

    st.caption(summary["risk_score_explanation"])

    # Önem derecesi grafiği
    st.divider()
    st.subheader("Güvenlik Açıklarının Önem Derecesi")

    severity_data = pd.DataFrame(
        {
            "Önem derecesi": list(
                summary["severity_counts"].keys()
            ),
            "Açık sayısı": list(
                summary["severity_counts"].values()
            ),
        }
    )

    st.bar_chart(
        severity_data.set_index("Önem derecesi")
    )

    # Paket bazlı sonuçlar
    st.divider()
    st.subheader("Paket Analiz Sonuçları")

    package_rows = []

    for result in scan_results:
        package_rows.append({
            "Paket": result["package"],
            "Sürüm": result["version"] or "Belirsiz",
            "Durum": result["status"],
            "Açık sayısı": len(result["vulnerabilities"]),
        })

    package_df = pd.DataFrame(package_rows)

    st.dataframe(
        package_df,
        use_container_width=True,
        hide_index=True,
    )

    # Güvenlik açığı detayları
    st.divider()
    st.subheader("Bulunan Güvenlik Açıkları")

    vulnerability_rows = []

    for result in scan_results:
        for vulnerability in result["vulnerabilities"]:
            vulnerability_rows.append({
                "Paket": result["package"],
                "Sürüm": result["version"],
                "Açık ID": vulnerability["id"],
                "Özet": vulnerability["summary"],
                "Önem": vulnerability["severity"],
                "Düzeltilmiş sürümler": ", ".join(
                    vulnerability["fixed_versions"]
                ) or "Belirtilmemiş",
                "OSV bağlantısı": vulnerability["details_url"],
            })

    if vulnerability_rows:
        vulnerability_df = pd.DataFrame(vulnerability_rows)

        st.dataframe(
            vulnerability_df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "OSV bağlantısı": st.column_config.LinkColumn(
                    "OSV bağlantısı"
                )
            },
        )
    else:
        st.success(
            "Sorgulanan kesin sürümlerde OSV tarafından "
            "bilinen bir güvenlik açığı kaydı bulunmadı."
        )

    # Analiz dışı kalan paketler
    unresolved = [
        result for result in scan_results
        if result["status"] == "Sürüm doğrulanamadı"
    ]

    if unresolved:
        st.warning(
            f"{len(unresolved)} paketin kesin sürümü belirtilmediği "
            "için sürüm bazlı güvenlik sorgusu yapılamadı."
        )

    # Sorgulama hataları
    failed = [
        result for result in scan_results
        if result["status"] == "Sorgulama başarısız"
    ]

    if failed:
        st.error(
            f"{len(failed)} paket için OSV sorgusu başarısız oldu."
        )

        for result in failed:
            st.write(
                f"- {result['package']}: {result['error']}"
            )

    # GitHub dosya uyarıları
    if repository_data["warnings"]:
        st.divider()
        st.subheader("Analiz Uyarıları")

        for warning in repository_data["warnings"]:
            st.warning(warning)


st.title("🛡️ DepGuard")
st.subheader("Open Source Software Vulnerability Detection and Risk Analysis")

st.write(
    "GitHub deposunun bağımlılıklarını analiz et, "
    "bilinen güvenlik açıklarını tespit et ve risk durumunu incele."
)

st.info(
    "İlk sürüm yalnızca herkese açık GitHub depolarının "
    "kök dizinindeki requirements.txt ve pyproject.toml "
    "dosyalarını inceler."
)

repo_url = st.text_input(
    "GitHub Repository URL",
    placeholder="https://github.com/psf/requests",
)

analyze_button = st.button(
    "🔍 Analizi Başlat",
    type="primary",
    use_container_width=True,
)

if analyze_button:

    if not repo_url.strip():
        st.error("Lütfen bir GitHub depo bağlantısı gir.")

    else:
        try:
            with st.spinner("GitHub deposu inceleniyor..."):

                repository_data = analyze_github_repository(
                    repo_url
                )

            dependencies = repository_data["dependencies"]

            if not dependencies:
                st.warning(
                    "Analiz edilebilecek Python bağımlılığı bulunamadı."
                )

                for warning in repository_data["warnings"]:
                    st.write(warning)

            else:
                with st.spinner(
                    f"{len(dependencies)} bağımlılık OSV.dev "
                    "üzerinden sorgulanıyor..."
                ):
                    scan_results = scan_dependencies(dependencies)

                st.session_state["repository_data"] = repository_data
                st.session_state["scan_results"] = scan_results

                st.success("Analiz tamamlandı.")

        except ValueError as error:
            st.error(str(error))

        except Exception as error:
            st.error(
                f"Analiz sırasında beklenmeyen bir hata oluştu: {error}"
            )


if (
    "repository_data" in st.session_state
    and "scan_results" in st.session_state
):
    show_results(
        st.session_state["repository_data"],
        st.session_state["scan_results"],
    )


st.divider()

st.caption(
    "DepGuard | Python · GitHub REST API · OSV.dev · Streamlit"
)