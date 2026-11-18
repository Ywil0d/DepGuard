import re
import tomllib
import requests

def get_latest_pypi_version(package_name: str) -> str | None:
    """Sürüm belirtilmemiş veya aralık verilmiş paketler için PyPI'dan en güncel sürümü çeker."""
    try:
        resp = requests.get(f"https://pypi.org/pypi/{package_name}/json", timeout=5)
        if resp.status_code == 200:
            return resp.json().get("info", {}).get("version")
    except Exception:
        pass
    return None

def parse_dependency_line(line: str) -> tuple[str, str | None, str]:
    """
    Tek bir bağımlılık satırını ayrıştırır.
    Dönüş: (paket_adi, surum, durum_notu)
    """
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("-"):
        return "", None, ""

    # Ortam belirteçlerini (; python_version < "3.10" vb.) temizle
    line = line.split(";")[0].strip()
    # Ekstra özellikleri ([security], [socks] vb.) temizle
    line = re.sub(r"\[.*?\]", "", line).strip()

    # Sabit sürüm (==) kontrolü
    exact_match = re.match(r"^([A-Za-z0-9_.-]+)\s*==\s*([A-Za-z0-9_.*+-]+)", line)
    if exact_match:
        return exact_match.group(1), exact_match.group(2), "Sabit sürüm doğrulandı"

    # Sürüm aralığı (>=, <=, ~=, >, <) kontrolü
    range_match = re.match(r"^([A-Za-z0-9_.-]+)\s*(?:>=|<=|~=|>|<|!=)\s*([0-9]+(?:\.[0-9]+)*)", line)
    if range_match:
        pkg_name = range_match.group(1)
        min_ver = range_match.group(2)
        latest_ver = get_latest_pypi_version(pkg_name)
        if latest_ver:
            return pkg_name, latest_ver, f"Aralık tanımı -> Güncel PyPI ({latest_ver}) baz alındı"
        return pkg_name, min_ver, f"Aralık alt sınırı ({min_ver}) baz alındı"

    # Sadece paket adı yazılmışsa
    name_only = re.match(r"^([A-Za-z0-9_.-]+)$", line)
    if name_only:
        pkg_name = name_only.group(1)
        latest_ver = get_latest_pypi_version(pkg_name)
        if latest_ver:
            return pkg_name, latest_ver, f"Sürüm belirtilmemiş -> Güncel PyPI ({latest_ver}) baz alındı"
        return pkg_name, None, "Sürüm doğrulanamadı"

    return "", None, ""

def parse_requirements_txt(content: str) -> list[dict]:
    packages = []
    for line in content.splitlines():
        name, version, note = parse_dependency_line(line)
        if name:
            packages.append({
                "name": name,
                "version": version or "Unknown",
                "note": note,
                "is_pinned": "==" in line.split(";", 1)[0] and version is not None,
            })
    return packages

def parse_pyproject_toml(content: str) -> list[dict]:
    packages = []
    try:
        data = tomllib.loads(content)
        deps = data.get("project", {}).get("dependencies", [])
        # Poetry desteği
        if not deps:
            poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
            deps = []
            for name, constraint in poetry_deps.items():
                if name.lower() == "python" or not isinstance(constraint, str) or constraint == "*":
                    continue
                if constraint.startswith(("^", "~")):
                    deps.append(f"{name}>={constraint.lstrip('^~')}")
                elif constraint.startswith(("<", ">", "=")):
                    deps.append(f"{name}{constraint}")
                else:
                    deps.append(f"{name}=={constraint}")

        for dep in deps:
            name, version, note = parse_dependency_line(dep)
            if name:
                packages.append({
                    "name": name,
                    "version": version or "Unknown",
                    "note": note,
                    "is_pinned": "==" in dep and version is not None,
                })
    except Exception as e:
        print(f"pyproject.toml ayrıştırma hatası: {e}")
    return packages