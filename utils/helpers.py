import re
from urllib.parse import urlparse

from packaging.utils import canonicalize_name


def parse_github_url(repo_url: str) -> tuple[str, str]:
    """
    GitHub depo bağlantısından owner ve repo adını çıkarır.

    Örnek:
    https://github.com/psf/requests
    -> ("psf", "requests")
    """

    if not repo_url or not repo_url.strip():
        raise ValueError("GitHub bağlantısı boş olamaz.")

    parsed = urlparse(repo_url.strip())

    if parsed.scheme not in ("https", "http"):
        raise ValueError("Bağlantı http veya https ile başlamalı.")

    if parsed.netloc.lower() != "github.com":
        raise ValueError("Yalnızca github.com bağlantıları destekleniyor.")

    parts = [part for part in parsed.path.strip("/").split("/") if part]

    if len(parts) != 2:
        raise ValueError(
            "Bağlantı şu formatta olmalı: "
            "https://github.com/kullanici/depo"
        )

    owner, repo = parts

    repo = re.sub(r"\.git$", "", repo)

    if not owner or not repo:
        raise ValueError("Geçersiz GitHub depo bağlantısı.")

    return owner, repo


def normalize_package_name(package_name: str) -> str:
    """
    Python paket isimlerini karşılaştırılabilir hale getirir.
    """

    return canonicalize_name(package_name)


def format_severity(severity: str | None) -> str:
    """
    Güvenlik seviyesi metnini standartlaştırır.
    """

    if not severity:
        return "Bilinmiyor"

    severity = severity.upper()

    allowed = {
        "CRITICAL": "Critical",
        "HIGH": "High",
        "MEDIUM": "Medium",
        "MODERATE": "Medium",
        "LOW": "Low",
        "NONE": "None",
    }

    return allowed.get(severity, "Bilinmiyor")