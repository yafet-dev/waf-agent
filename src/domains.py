"""
Domain validation and safe path construction.

Every feature in this agent turns a caller-supplied domain into a filesystem
path, and the agent runs as root. This module is the single chokepoint for
that conversion, so the rules cannot drift between geo, IP blocking, and WAF
toggling.

Two independent guards, deliberately redundant:

1. normalize_domain() rejects anything that is not a plain hostname. It
   rejects rather than sanitizes -- a domain containing "/" or ".." is a bug
   or an attack, not something to quietly rewrite into a different domain.
2. safe_domain_path() re-checks that the finished path really sits inside its
   base directory. If a future edit weakens the pattern, this still holds.
"""

import re
from pathlib import Path

from fastapi import HTTPException

# A hostname: dot-separated labels of letters, digits and hyphens, where no
# label starts or ends with a hyphen. At least two labels, so a bare
# "localhost" or a single word cannot become a filename.
#
# \Z rather than $ is deliberate: in Python, $ also matches immediately before
# a trailing newline, so "evil.com\n" would slip through a $-anchored pattern.
DOMAIN_RE = re.compile(
    r'\A(?=.{1,253}\Z)'
    r'[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?'
    r'(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+\Z'
)


def normalize_domain(domain: str) -> str:
    """
    Validate a caller-supplied domain and return its canonical form.

    Accepts a domain or subdomain: "example.com", "waf.example.com",
    "xn--80ak6aa92e.com". Surrounding whitespace and a trailing root dot are
    stripped, and the result is lowercased.

    Raises HTTPException(400) for everything else, including path separators,
    "..", absolute paths, shell metacharacters, null bytes, wildcards, bare
    single-label names, and anything over 253 characters.
    """
    if not isinstance(domain, str) or not domain.strip():
        raise HTTPException(status_code=400, detail="Domain is required")

    candidate = domain.strip().lower().rstrip('.')

    if not DOMAIN_RE.match(candidate):
        raise HTTPException(
            status_code=400,
            detail=(
                f"Invalid domain '{domain}'. Expected a domain or subdomain "
                "such as 'example.com' or 'waf.example.com'."
            ),
        )

    return candidate


def sanitize_domain_for_variable(domain: str) -> str:
    """
    Convert a domain into a valid nginx variable name fragment.

    Only safe on an already-validated domain; the caller is expected to have
    run normalize_domain() first.
    """
    return domain.replace('.', '_').replace('-', '_')


def safe_domain_path(
    base: Path, domain: str, suffix: str = "", prefix: str = ""
) -> Path:
    """
    Build `base/<prefix><domain><suffix>`, validating the domain and confirming
    the result stays inside `base`.

    The containment check is a backstop for normalize_domain(), not a
    replacement: it catches a weakened pattern, a symlinked base directory, or
    a platform quirk in path joining.
    """
    validated = normalize_domain(domain)
    candidate = base / f"{prefix}{validated}{suffix}"

    # Compare resolved forms so "..", symlinks and platform separators are all
    # collapsed before the check.
    resolved_base = Path(base).resolve()
    resolved_candidate = candidate.resolve()

    if resolved_base != resolved_candidate.parent:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Refusing to build a path outside {base} for domain "
                f"'{domain}'."
            ),
        )

    return candidate
