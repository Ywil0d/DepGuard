def calculate_risk(scan_results: list[dict]) -> dict:
    """
    Güvenlik taraması sonuçlarından risk özeti oluşturur.

    Ağırlıklar:
    Critical = 25
    High     = 15
    Medium   = 8
    Low      = 3

    Risk puanı en fazla 100 olabilir.
    """

    severity_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Bilinmiyor": 0,
    }

    vulnerable_packages = set()
    vulnerability_ids = set()

    unresolved_packages = 0
    failed_packages = 0

    weights = {
        "Critical": 25,
        "High": 15,
        "Medium": 8,
        "Low": 3,
        "Bilinmiyor": 0,
    }

    weighted_score = 0

    for result in scan_results:

        if result["status"] == "Sürüm doğrulanamadı":
            unresolved_packages += 1
            continue

        if result["status"] == "Sorgulama başarısız":
            failed_packages += 1
            continue

        for vulnerability in result.get("vulnerabilities", []):

            severity = vulnerability.get(
                "severity",
                "Bilinmiyor",
            )

            if severity not in severity_counts:
                severity = "Bilinmiyor"

            severity_counts[severity] += 1

            vulnerable_packages.add(result["package"])

            vulnerability_ids.add(vulnerability["id"])

            weighted_score += weights[severity]

    risk_score = min(100, weighted_score)

    if risk_score >= 75:
        risk_level = "Kritik"
    elif risk_score >= 40:
        risk_level = "Yüksek"
    elif risk_score >= 15:
        risk_level = "Orta"
    elif risk_score > 0:
        risk_level = "Düşük"
    else:
        risk_level = "Bilinen açık bulunmadı"

    return {
        "total_packages": len(scan_results),
        "scanned_packages": (
            len(scan_results)
            - unresolved_packages
            - failed_packages
        ),
        "vulnerable_packages": len(vulnerable_packages),
        "total_vulnerabilities": len(vulnerability_ids),
        "unresolved_packages": unresolved_packages,
        "failed_packages": failed_packages,
        "severity_counts": severity_counts,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_score_explanation": (
            "Critical: 25, High: 15, Medium: 8, Low: 3 "
            "ağırlıklarıyla hesaplanan ve 100 ile sınırlandırılan "
            "DepGuard içi gösterge. Resmi CVSS puanı değildir."
        ),
    }