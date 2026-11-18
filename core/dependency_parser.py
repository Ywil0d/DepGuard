import re
import tomllib

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name


def _build_dependency(
    name: str,
    version_spec: str,
    source_file: str
) -> dict:
    """
    Bağımlılık için standart bir veri yapısı oluşturur.
    """

    version_spec = (version_spec or "").strip()

    pinned_version = None
    is_pinned = False

    # Yalnızca tek ve kesin == sürümünü sabit sürüm kabul ediyoruz.
    # Örnek: ==2.31.0
    if version_spec.startswith("==") and "," not in version_spec:
        candidate = version_spec[2:].strip()

        if candidate and "*" not in candidate:
            pinned_version = candidate
            is_pinned = True

    return {
        "name": name.strip(),
        "normalized_name": canonicalize_name(name),
        "version_spec": version_spec or "Belirtilmemiş",
        "version": pinned_version,
        "is_pinned": is_pinned,
        "source_file": source_file,
    }


def parse_requirements_txt(content: str) -> list[dict]:
    """
    requirements.txt içeriğini ayrıştırır.

    Örnek:
    requests==2.31.0
    django>=4.2
    flask
    """

    dependencies = []
    seen = set()

    for raw_line in content.splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        if line.startswith(("-", "--")):
            # -r, -e, --index-url gibi pip seçeneklerini
            # bu ilk sürümde analiz etmiyoruz.
            continue

        # Inline yorumları temizle.
        line = re.split(r"\s+#", line, maxsplit=1)[0].strip()

        try:
            requirement = Requirement(line)

            # Doğrudan URL bağımlılıklarını bu sürümde
            # sürüm bazlı OSV sorgusuna dahil etmiyoruz.
            if requirement.url:
                continue

            name = requirement.name
            version_spec = str(requirement.specifier)

            dependency = _build_dependency(
                name=name,
                version_spec=version_spec,
                source_file="requirements.txt",
            )

            key = dependency["normalized_name"]

            if key not in seen:
                dependencies.append(dependency)
                seen.add(key)

        except Exception:
            # Hatalı veya desteklenmeyen satırı atla.
            continue

    return dependencies


def _parse_poetry_dependencies(poetry_dependencies: dict) -> list[dict]:
    """
    Poetry bağımlılıklarını ayrıştırır.
    """

    dependencies = []

    for name, value in poetry_dependencies.items():

        # Python sürümü bir paket bağımlılığı değildir.
        if name.lower() == "python":
            continue

        if isinstance(value, str):
            version_spec = value

        elif isinstance(value, dict):
            # Git, path veya URL bağımlılıklarını şimdilik atla.
            if any(key in value for key in ("git", "path", "url")):
                continue

            version_spec = str(value.get("version", ""))

        else:
            continue

        # Poetry sürüm ifadelerini PEP 440 formatına
        # otomatik çevirmiyoruz. Örneğin ^1.2 kesin sürüm değildir.
        dependency = _build_dependency(
            name=name,
            version_spec=version_spec,
            source_file="pyproject.toml",
        )

        dependencies.append(dependency)

    return dependencies


def parse_pyproject_toml(content: str) -> list[dict]:
    """
    pyproject.toml dosyasındaki bağımlılıkları ayrıştırır.

    Desteklenen bölümler:
    - [project] dependencies
    - [tool.poetry.dependencies]
    """

    try:
        data = tomllib.loads(content)
    except tomllib.TOMLDecodeError as error:
        raise ValueError(f"pyproject.toml okunamadı: {error}") from error

    dependencies = []

    # Standart PEP 621 yapısı.
    project_dependencies = data.get("project", {}).get("dependencies", [])

    for item in project_dependencies:
        try:
            requirement = Requirement(item)

            if requirement.url:
                continue

            dependencies.append(
                _build_dependency(
                    name=requirement.name,
                    version_spec=str(requirement.specifier),
                    source_file="pyproject.toml",
                )
            )

        except Exception:
            continue

    # Poetry yapısı.
    poetry_dependencies = (
        data.get("tool", {})
        .get("poetry", {})
        .get("dependencies", {})
    )

    if isinstance(poetry_dependencies, dict):
        dependencies.extend(
            _parse_poetry_dependencies(poetry_dependencies)
        )

    # Aynı paket iki yerde tanımlanmışsa tek kayıt tut.
    unique_dependencies = {}
    for dependency in dependencies:
        key = dependency["normalized_name"]

        if key not in unique_dependencies:
            unique_dependencies[key] = dependency

    return list(unique_dependencies.values())


def merge_dependencies(*dependency_lists: list[dict]) -> list[dict]:
    """
    Birden fazla bağımlılık listesini birleştirir.
    Aynı paket tekrar ederse kesin sürüm bilgisi olanı tercih eder.
    """

    merged = {}

    for dependency_list in dependency_lists:
        for dependency in dependency_list:
            key = dependency["normalized_name"]

            if key not in merged:
                merged[key] = dependency

            elif dependency["is_pinned"] and not merged[key]["is_pinned"]:
                merged[key] = dependency

    return list(merged.values())