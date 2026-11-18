import json
from pathlib import Path
import requests
import pandas as pd
import matplotlib.pyplot as plt
import streamlit as st

from core.github_analyzer import parse_repo_url, fetch_dependency_files
from core.dependency_parser import parse_requirements_txt, parse_pyproject_toml
from core.osv_scanner import check_package_vulnerabilities
from core.risk_analyzer import calculate_risk_metrics

st.set_page_config(page_title="DepGuard", page_icon="🛡️", layout="wide")
st.title("DepGuard - Python Güvenlik ve Bağımlılık Analiz Platformu")

# Yan Menü
with st.sidebar:
    st.header("⚙️ Genel Ayarlar")
    github_token = st.text_input(
        "GitHub Token (Opsiyonel - Rate Limit için)",
        type="password",
        help="GitHub API saatlik istek sınırına (60 istek) takılmamak için girebilirsin."
    )
    st.info("Sol menüden token girersen hem depo taraması hem de Advisory analizi sınır takılmadan çalışır.")

# İki Sekmeli Yapı
tab1, tab2 = st.tabs([
    "🔍 Depo Bağımlılık Analizi (OSV.dev)",
    "📊 GitHub Advisory (pip) Veri Analizi"
])

# ==============================================================================
# SEKME 1: DEPO BAĞIMLILIK ANALİZİ
# ==============================================================================
with tab1:
    col_input, col_btn = st.columns([4, 1])
    with col_input:
        repo_input = st.text_input(
            "GitHub Repository (owner/repo veya tam URL)",
            value="psf/requests",
            label_visibility="collapsed",
            placeholder="Örn: psf/requests"
        )
    with col_btn:
        scan_btn = st.button("Analizi Başlat", type="primary", use_container_width=True)

    if scan_btn and repo_input:
        try:
            owner, repo = parse_repo_url(repo_input)
            with st.spinner(f"{owner}/{repo} bağımlılık dosyaları taranıyor..."):
                files = fetch_dependency_files(owner, repo, github_token or None)

            if not files:
                st.error("Depoda `requirements.txt` veya `pyproject.toml` dosyası bulunamadı.")
                st.stop()

            packages = []
            if "requirements.txt" in files:
                packages.extend(parse_requirements_txt(files["requirements.txt"]))
            elif "pyproject.toml" in files:
                packages.extend(parse_pyproject_toml(files["pyproject.toml"]))

            if not packages:
                st.warning("Bağımlılık dosyasında ayrıştırılabilir paket bulunamadı.")
                st.stop()

            scan_results = []
            all_vulns_flat = []

            with st.spinner("OSV.dev güvenlik açıkları sorgulanıyor..."):
                for pkg in packages:
                    res = check_package_vulnerabilities(pkg["name"], pkg["version"])
                    scan_results.append({
                        "Package": pkg["name"],
                        "Version": pkg["version"],
                        "Status": pkg["note"] if pkg["version"] != "Unknown" else res["status"],
                        "Vulnerabilities": len(res["vulns"]),
                        "vulns": res["vulns"],
                        "version": pkg["version"],
                        "status": res["status"]
                    })
                    for v in res["vulns"]:
                        all_vulns_flat.append({
                            "Package": pkg["name"],
                            "Version": pkg["version"],
                            "Vulnerability ID": v["id"],
                            "Aliases": v["aliases"],
                            "Severity": v["severity"],
                            "Summary": v["summary"]
                        })

            metrics = calculate_risk_metrics(scan_results)

            st.subheader("Repository Overview")
            st.markdown(f"**Repository:** [{owner}/{repo}](https://github.com/{owner}/{repo})")
            st.caption(f"Dependency files: {', '.join(files.keys())}")
            st.divider()

            st.subheader("Security Overview")
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Total Packages", metrics["total_packages"])
            c2.metric("Vulnerable Packages", metrics["vulnerable_packages"])
            c3.metric("Vulnerability Records", metrics["total_vulns"])
            c4.metric("DepGuard Risk Indicator", f"{metrics['risk_score']}/100")

            st.subheader(f"Overall Assessment: {metrics['assessment']}")
            st.caption("Critical: 25, High: 15, Medium: 8, Low: 3 ağırlıklarıyla hesaplanan ve 100 ile sınırlandırılan DepGuard içi gösterge. Resmi CVSS puanı değildir.")

            if metrics["unknown_count"] > 0:
                st.warning(f"Bilgi: {metrics['unknown_count']} paketin sabit sürümü olmadığı için PyPI üzerinden çözümlendi veya genel sorgulandı.")

            st.divider()
            st.subheader("Vulnerability Severity")
            if metrics["total_vulns"] > 0:
                sev_df = pd.DataFrame(list(metrics["severity_counts"].items()), columns=["Severity", "Count"])
                st.bar_chart(sev_df.set_index("Severity"))
            else:
                st.info("Bu sürümler için kayıtlı güvenlik açığı bulunamadı.")

            st.divider()
            st.subheader("Package Analysis")
            display_df = pd.DataFrame(scan_results)[["Package", "Version", "Status", "Vulnerabilities"]]
            st.dataframe(display_df, use_container_width=True, hide_index=True)

            csv_data = display_df.to_csv(index=False).encode("utf-8")
            st.download_button(
                "⬇️ Paket Sonuçlarını İndir (CSV)",
                data=csv_data,
                file_name=f"{repo}_depguard.csv",
                mime="text/csv"
            )

            st.divider()
            st.subheader("Vulnerability Details")
            if all_vulns_flat:
                st.dataframe(pd.DataFrame(all_vulns_flat), use_container_width=True, hide_index=True)
            else:
                st.info("Görüntülenecek güvenlik açığı detayı yok.")

        except Exception as e:
            st.error(f"Analiz sırasında hata oluştu: {e}")

# ==============================================================================
# SEKME 2: GITHUB ADVISORY DATABASE (PIP) VERİ ANALİZİ
# ==============================================================================
with tab2:
    st.subheader("GitHub Advisory Database – pip Ekosistemi Analizi")
    st.markdown("GitHub API üzerinden `pip` ekosistemine ait incelenmiş (*reviewed*) son güvenlik açığı kayıtlarını çeker, istatistikleri hesaplar ve `veri/` ile `sonuc/` klasörlerine kaydeder.")

    col_limit, col_run = st.columns([3, 1])
    with col_limit:
        per_page = st.slider("Çekilecek Kayıt Sayısı", min_value=10, max_value=100, value=100, step=10)
    with col_run:
        st.write("")
        adv_btn = st.button("Advisory Verisini Çek ve Analiz Et", type="primary", use_container_width=True)

    if adv_btn:
        try:
            with st.spinner("GitHub Advisory Database verileri çekiliyor..."):
                Path("veri").mkdir(exist_ok=True)
                Path("sonuc").mkdir(exist_ok=True)

                url = "https://api.github.com/advisories"
                headers = {
                    "User-Agent": "DepGuard-Advisory-Fetcher",
                    "Accept": "application/vnd.github+json"
                }
                if github_token:
                    headers["Authorization"] = f"token {github_token}"

                params = {
                    "ecosystem": "pip",
                    "type": "reviewed",
                    "per_page": per_page,
                    "sort": "published",
                    "direction": "desc"
                }

                r = requests.get(url, params=params, headers=headers, timeout=30)
                r.raise_for_status()
                kayitlar = r.json()

                # Ham JSON kaydı
                with open("veri/advisory_ham.json", "w", encoding="utf-8") as f:
                    json.dump(kayitlar, f, ensure_ascii=False, indent=2)

                # Yapılandırılmış tablo oluşturma
                satirlar = []
                for k in kayitlar:
                    vul = k.get("vulnerabilities") or []
                    satirlar.append({
                        "ghsa_id": k.get("ghsa_id"),
                        "cve_id": k.get("cve_id"),
                        "ozet": k.get("summary"),
                        "onem": (k.get("severity") or "unknown").lower(),
                        "cvss_puani": (k.get("cvss") or {}).get("score"),
                        "yayin_tarihi": k.get("published_at"),
                        "paketler": "; ".join(sorted({v["package"]["name"] for v in vul if v.get("package")})),
                        "etkilenen_surum": "; ".join(v.get("vulnerable_version_range") or "" for v in vul),
                    })

                veri = pd.DataFrame(satirlar)
                veri["yayin_tarihi"] = pd.to_datetime(veri["yayin_tarihi"])

                # Normalize edilmiş CSV kaydı
                norm_veri = pd.json_normalize(kayitlar)
                norm_veri.to_csv("sonuc/kullanilan_veri.csv", index=False)

            st.success("✅ Veriler başarıyla çekildi ve `veri/advisory_ham.json` ile `sonuc/kullanilan_veri.csv` dosyalarına kaydedildi.")

            # Özet Metrikler
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Toplam Kayıt Sayısı", len(veri))
            ort_cvss = round(veri["cvss_puani"].mean(), 2) if not veri["cvss_puani"].isna().all() else 0.0
            m2.metric("Ortalama CVSS Puanı (0-10)", ort_cvss)
            kumulatif_cvss = round(veri["cvss_puani"].sum(), 2)
            m3.metric("Kümülatif Risk Skoru Toplamı", kumulatif_cvss)
            m4.metric("Eksik CVSS Sayısı", int(veri["cvss_puani"].isna().sum()))

            st.divider()

            # Grafik ve Önem Dağılımı Yan Yana
            col_chart, col_stats = st.columns([2, 1])

            with col_chart:
                st.subheader("Önem Derecesine Göre Dağılım Grafiği")
                sira = ["low", "medium", "high", "critical"]
                sayim = veri["onem"].value_counts().reindex(sira).fillna(0)

                fig, ax = plt.subplots(figsize=(8, 4))
                bars = ax.bar(sayim.index, sayim.values, color="teal")
                ax.set_xlabel("Önem derecesi")
                ax.set_ylabel("Güvenlik açığı kaydı sayısı (adet)")
                ax.set_title(f"GitHub Advisory Database – pip paketleri (ilk {len(veri)} kayıt)")
                for bar in bars:
                    yval = bar.get_height()
                    ax.text(bar.get_x() + bar.get_width()/2, yval + 0.3, int(yval), ha="center", va="bottom", fontsize=9)
                fig.tight_layout()
                fig.savefig("sonuc/grafik.png", dpi=160)
                st.pyplot(fig)

            with col_stats:
                st.subheader("Önem Dağılımı ve Eksik Veri Özeti")
                st.write("**Önem Dağılımı:**")
                st.dataframe(sayim.rename("Adet"), use_container_width=True)
                st.write("**Sütun Bazlı Eksik Değerler:**")
                st.dataframe(veri.isna().sum().rename("Eksik Sayısı"), use_container_width=True)

            st.divider()
            st.subheader("Çekilen Güvenlik Açığı Kayıtları (Önizleme)")
            st.dataframe(veri, use_container_width=True, hide_index=True)

            # İndirme Butonları
            dl1, dl2, dl3 = st.columns(3)
            with dl1:
                st.download_button(
                    "⬇️ İşlenmiş Tabloyu İndir (CSV)",
                    data=veri.to_csv(index=False).encode("utf-8"),
                    file_name="pip_advisory_ozet.csv",
                    mime="text/csv"
                )
            with dl2:
                with open("veri/advisory_ham.json", "rb") as jf:
                    st.download_button(
                        "⬇️ Ham JSON Kanıtını İndir",
                        data=jf.read(),
                        file_name="advisory_ham.json",
                        mime="application/json"
                    )
            with dl3:
                with open("sonuc/grafik.png", "rb") as pf:
                    st.download_button(
                        "⬇️ Grafiği İndir (PNG)",
                        data=pf.read(),
                        file_name="grafik.png",
                        mime="image/png"
                    )

        except requests.exceptions.HTTPError as http_err:
            st.error(f"GitHub API HTTP Hatası: {http_err}. Yan menüden bir GitHub Token girerek tekrar deneyebilirsin.")
        except Exception as e:
            st.error(f"Beklenmeyen bir hata oluştu: {e}")