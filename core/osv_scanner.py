import requests

from utils.helpers import format_severity


OSV_QUERY_URL = "https://api.osv.dev/v1/query"


def _extract_severity(vulnerability: dict) -> str:
    """
    OSV kaydından bilinen önem derecesini çıkarmaya çalışır.
    """

    # Önce advisory genelindeki database_specific alanına bak.
    database_specific = vulnerability.get("database_specific", {})

    severity = database_specific.get("severity")

    if severity:
        return format_severity(severity)

    # Ardından etkilenen paketlerin metadata alanlarına bak.
    for affected in vulnerability.get("affected", []):

        ecosystem_specific = affected.get("ecosystem_specific", {})
        database_specific = affected.get("database_specific", {})

        severity = (
            ecosystem_specific.get("severity")
            or database_specific.get("severity")
        )

        if severity:
            return format_severity(severity)

    return "Bilinmiyor"


def _extract_fixed_versions(vulnerability: dict) -> list[str]:
    """
    OSV affected ranges içinden düzeltilmiş sürümleri çıkarır.
    """

    fixed_versions = set()

    for affected in vulnerability.get("affected", []):
        for version_range in affected.get("ranges", []):
            for event in version_range.get("events", []):
                fixed = event.get("fixed")

                if fixed:
                    fixed_versions.add(fixed)

    return sorted(fixed_versions)


def scan_dependency(dependency: dict) -> dict:
    """
    Tek bir Python bağımlılığını OSV üzerinden tarar.
    """

    if not dependency.get("is_pinned"):
        return {
            "package": dependency["name"],
            "version": None,
            "status": "Sürüm doğrulanamadı",
            "vulnerabilities": [],
            "error": None,
        }

    payload = {
        "package": {
            "name": dependency["name"],
            "ecosystem": "PyPI",
        },
        "version": dependency["version"],
    }

    try:
        response = requests.post(
            OSV_QUERY_URL,
            json=payload,
            timeout=25,
        )

        response.raise_for_status()

        data = response.json()

        vulnerabilities = []

        for vulnerability in data.get("vulns", []):
            vulnerabilities.append({
                "id": vulnerability.get("id", "Bilinmiyor"),
                "summary": vulnerability.get(
                    "summary",
                    "Açıklama bulunamadı.",
                ),
                "severity": _extract_severity(vulnerability),
                "fixed_versions": _extract_fixed_versions(
                    vulnerability
                ),
                "details_url": (
                    "https://osv.dev/vulnerability/"
                    + vulnerability.get("id", "")
                ),
            })

        return {
            "package": dependency["name"],
            "version": dependency["version"],
            "status": (
                "Güvenlik açığı bulundu"
                if vulnerabilities
                else "Kayıtlı açık bulunamadı"
            ),
            "vulnerabilities": vulnerabilities,
            "error": None,
        }

    except requests.RequestException as error:
        return {
            "package": dependency["name"],
            "version": dependency["version"],
            "status": "Sorgulama başarısız",
            "vulnerabilities": [],
            "error": str(error),
        }


def scan_dependencies(dependencies: list[dict]) -> list[dict]:
    """
    Bağımlılık listesindeki bütün paketleri tarar.
    """

    results = []

    for dependency in dependencies:
        results.append(scan_dependency(dependency))

    return results