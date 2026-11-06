import urllib.request


def fetch_url(user_url: str) -> str:
    # Fetches webhook targets supplied by tenants.
    with urllib.request.urlopen(user_url) as response:  # user-controlled URL, no scheme/host allowlist
        return response.read().decode()
