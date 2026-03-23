from typing import Optional
from square_authentication.configuration import ALLOWED_REDIRECT_URLS

def validate_redirect_url(redirect_url: str) -> bool:
    """
    Validates if the provided redirect_url is in the whitelist or starts with an allowed base URL.
    """
    if not redirect_url:
        return False
    
    for allowed_url in ALLOWED_REDIRECT_URLS:
        if redirect_url.startswith(allowed_url):
            return True
    return False

def construct_clickable_link(redirect_url: str, params: dict) -> Optional[str]:
    """
    Constructs a clickable link by appending parameters to the redirect_url.
    """
    if not validate_redirect_url(redirect_url):
        return None
    
    separator = "&" if "?" in redirect_url else "?"
    query_string = "&".join(f"{k}={v}" for k, v in params.items())
    return f"{redirect_url}{separator}{query_string}"
