import requests

OSV_API_URL = "https://api.osv.dev/v1/query"

def check_package_vulnerabilities(package_name: str, version: str) -> dict:
    payload = {
        "package": {
            "name": package_name,
            "ecosystem": "PyPI"
        }
    }
    if version and version != "Unknown":
        payload["version"] = version

    try:
        resp = requests.post(OSV_API_URL, json=payload, timeout=10)
        if resp.status_code != 200:
            return {"status": "API Hatası", "vulns": [], "error": f"HTTP {resp.status_code}"}

        data = resp.json()
        vulns = data.get("vulns", [])
        parsed_vulns = []

        for v in vulns:
            severity = "MEDIUM"
            db_specific = v.get("database_specific", {})
            if "severity" in db_specific:
                severity = db_specific["severity"].upper()
            elif v.get("severity"):
                score_str = str(v["severity"][0].get("score", ""))
                if "CRITICAL" in score_str:
                    severity = "CRITICAL"
                elif "HIGH" in score_str:
                    severity = "HIGH"
                elif "LOW" in score_str:
                    severity = "LOW"

            parsed_vulns.append({
                "id": v.get("id", "N/A"),
                "summary": v.get("summary", v.get("details", "Açıklama bulunmuyor")[:150]),
                "severity": severity,
                "aliases": ", ".join(v.get("aliases", []))
            })

        status_text = "Doğrulandı" if (version and version != "Unknown") else "Sürüm doğrulanamadı"
        return {
            "status": status_text,
            "vulns": parsed_vulns,
            "error": None
        }
    except Exception as e:
        return {"status": "Bağlantı Hatası", "vulns": [], "error": str(e)}