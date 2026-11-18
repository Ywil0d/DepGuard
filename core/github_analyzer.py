import requests
import base64

def parse_repo_url(repo_input: str) -> tuple[str, str]:
    clean = repo_input.strip().rstrip("/")
    if "github.com/" in clean:
        clean = clean.split("github.com/")[-1]
    if clean.endswith(".git"):
        clean = clean[:-4]
    parts = clean.split("/")
    if len(parts) < 2:
        raise ValueError("Geçersiz GitHub depo formatı. Örnek: psf/requests")
    return parts[0], parts[1]

def _fetch_via_raw_fallback(owner: str, repo: str) -> dict[str, str]:
    """GitHub API limiti dolduğunda raw.githubusercontent.com üzerinden doğrudan dosya çeker."""
    found_files = {}
    branches = ["main", "master"]
    filenames = ["requirements.txt", "pyproject.toml"]

    for branch in branches:
        for filename in filenames:
            raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{filename}"
            resp = requests.get(raw_url, timeout=10)
            if resp.status_code == 200 and resp.text.strip():
                found_files[filename] = resp.text
        if found_files:
            break

    return found_files

def fetch_dependency_files(owner: str, repo: str, token: str | None = None) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "DepGuard-Scanner"
    }
    if token:
        headers["Authorization"] = f"token {token}"

    repo_url = f"https://api.github.com/repos/{owner}/{repo}"
    repo_resp = requests.get(repo_url, headers=headers, timeout=10)

    # Rate limit (403/429) durumunda otomatik olarak Raw URL yedeğine geç
    if repo_resp.status_code in (403, 429):
        fallback_files = _fetch_via_raw_fallback(owner, repo)
        if fallback_files:
            return fallback_files
        raise RuntimeError(
            "GitHub API istek sınırı doldu ve kök dizinde dosya bulunamadı. "
            "Alt klasörleri taramak için sol menüden ücretsiz bir GitHub Token girebilirsin."
        )

    if repo_resp.status_code == 404:
        raise RuntimeError(f"'{owner}/{repo}' deposu bulunamadı veya gizli (Private).")
    repo_resp.raise_for_status()

    default_branch = repo_resp.json().get("default_branch", "main")

    tree_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{default_branch}?recursive=1"
    tree_resp = requests.get(tree_url, headers=headers, timeout=10)

    if tree_resp.status_code in (403, 429):
        return _fetch_via_raw_fallback(owner, repo)

    tree_resp.raise_for_status()

    tree_items = tree_resp.json().get("tree", [])
    target_paths = [
        item["path"] for item in tree_items
        if item["type"] == "blob" and (
            item["path"].endswith("requirements.txt") or item["path"].endswith("pyproject.toml")
        )
    ]

    found_files = {}
    for file_path in target_paths[:3]:
        raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{default_branch}/{file_path}"
        resp = requests.get(raw_url, timeout=10)
        if resp.status_code == 200:
            found_files[file_path] = resp.text

    return found_files