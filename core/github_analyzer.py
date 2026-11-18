import base64

import requests

from core.dependency_parser import (
    parse_requirements_txt,
    parse_pyproject_toml,
    merge_dependencies,
)
from utils.helpers import parse_github_url


GITHUB_API = "https://api.github.com"


def _get_github_file(owner: str, repo: str, file_path: str):
    """
    GitHub deposundan tek bir dosyanın içeriğini alır.
    """

    url = f"{GITHUB_API}/repos/{owner}/{repo}/contents/{file_path}"

    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "DepGuard-Security-Analyzer",
    }

    response = requests.get(
        url,
        headers=headers,
        timeout=20,
    )

    if response.status_code == 404:
        return None

    if response.status_code == 403:
        raise RuntimeError(
            "GitHub API erişim sınırına ulaşılmış olabilir. "
            "Bir süre sonra tekrar dene."
        )

    response.raise_for_status()

    file_data = response.json()

    if file_data.get("type") != "file":
        return None

    content = file_data.get("content", "")
    encoding = file_data.get("encoding")

    if encoding != "base64":
        raise RuntimeError(
            f"{file_path} dosyasının kodlaması desteklenmiyor."
        )

    decoded = base64.b64decode(content).decode("utf-8")

    return decoded


def analyze_github_repository(repo_url: str) -> dict:
    """
    GitHub deposunu inceler.

    Şimdilik yalnızca kök dizindeki:
    - requirements.txt
    - pyproject.toml

    dosyalarını analiz eder.
    """

    owner, repo = parse_github_url(repo_url)

    result = {
        "owner": owner,
        "repo": repo,
        "repository_url": f"https://github.com/{owner}/{repo}",
        "files_found": [],
        "dependencies": [],
        "warnings": [],
    }

    all_dependencies = []

    # requirements.txt
    try:
        requirements_content = _get_github_file(
            owner,
            repo,
            "requirements.txt",
        )

        if requirements_content is not None:
            result["files_found"].append("requirements.txt")

            dependencies = parse_requirements_txt(
                requirements_content
            )

            all_dependencies.append(dependencies)

    except requests.RequestException as error:
        result["warnings"].append(
            f"requirements.txt alınamadı: {error}"
        )

    except Exception as error:
        result["warnings"].append(str(error))

    # pyproject.toml
    try:
        pyproject_content = _get_github_file(
            owner,
            repo,
            "pyproject.toml",
        )

        if pyproject_content is not None:
            result["files_found"].append("pyproject.toml")

            dependencies = parse_pyproject_toml(
                pyproject_content
            )

            all_dependencies.append(dependencies)

    except requests.RequestException as error:
        result["warnings"].append(
            f"pyproject.toml alınamadı: {error}"
        )

    except Exception as error:
        result["warnings"].append(str(error))

    result["dependencies"] = merge_dependencies(
        *all_dependencies
    )

    if not result["files_found"]:
        result["warnings"].append(
            "Depo kök dizininde desteklenen bağımlılık dosyası bulunamadı."
        )

    return result