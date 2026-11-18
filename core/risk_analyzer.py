SEVERITY_WEIGHTS = {
    "CRITICAL": 25,
    "HIGH": 15,
    "MEDIUM": 8,
    "LOW": 3
}

def calculate_risk_metrics(scan_results: list[dict]) -> dict:
    total_packages = len(scan_results)
    vulnerable_packages = 0
    total_vulns = 0
    raw_score = 0
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    unknown_count = 0
    failed_count = 0

    for item in scan_results:
        if item["version"] == "Unknown":
            unknown_count += 1
        if "Hatası" in item["status"]:
            failed_count += 1

        vulns = item.get("vulns", [])
        if vulns:
            vulnerable_packages += 1
            total_vulns += len(vulns)
            for v in vulns:
                sev = v.get("severity", "MEDIUM").upper()
                if sev not in severity_counts:
                    sev = "MEDIUM"
                severity_counts[sev] += 1
                raw_score += SEVERITY_WEIGHTS[sev]

    risk_score = min(100, raw_score)

    if total_packages == 0 or (unknown_count == total_packages and total_vulns == 0):
        assessment = "Analiz tamamlanamadı (Sürümler doğrulanamadı)"
    elif risk_score == 0:
        assessment = "Bilinen açık bulunmadı"
    elif risk_score < 25:
        assessment = "Düşük Risk"
    elif risk_score < 60:
        assessment = "Orta Risk"
    else:
        assessment = "Yüksek Risk"

    return {
        "total_packages": total_packages,
        "vulnerable_packages": vulnerable_packages,
        "total_vulns": total_vulns,
        "risk_score": risk_score,
        "severity_counts": severity_counts,
        "unknown_count": unknown_count,
        "failed_count": failed_count,
        "assessment": assessment
    }