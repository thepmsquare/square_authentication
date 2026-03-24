from typing import Optional


def construct_clickable_link(redirect_url: str, params: dict) -> Optional[str]:


    separator = "&" if "?" in redirect_url else "?"
    query_string = "&".join(f"{k}={v}" for k, v in params.items())
    return f"{redirect_url}{separator}{query_string}"