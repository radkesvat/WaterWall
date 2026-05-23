import pytest
import re
import urllib.parse


# Adversarial HTTP/2 path payloads relevant to authorization bypass via improper path validation
ADVERSARIAL_PATHS = [
    # Path traversal attempts
    "/service/../admin/method",
    "/service/../../etc/passwd",
    "/./service/method",
    "/../../../etc/shadow",
    "/service/%2e%2e/admin",
    "/service/%2e%2e%2f%2e%2e%2fadmin",
    "/service/..%2fadmin",
    "/service/%252e%252e/admin",
    # Double encoding
    "/service/%252F%252F/method",
    "/service/%25%32%65%25%32%65/admin",
    # Null byte injection
    "/service/method\x00/admin",
    "/service/method%00/admin",
    # Unicode normalization tricks
    "/service/\u002e\u002e/admin",
    "/service/\uff0e\uff0e/admin",
    "/service/method\u200b/admin",
    # HTTP/2 specific path manipulation
    "//service/method",
    "/service//method",
    "///admin",
    "/service/method//",
    # Query string injection
    "/service/method?override=/admin",
    "/service/method?path=/admin/secret",
    # Fragment injection
    "/service/method#/admin",
    # Mixed case bypass attempts
    "/SERVICE/METHOD",
    "/Service/Method",
    # Whitespace injection
    "/service/ method",
    "/service/method ",
    "/ service/method",
    # Special characters
    "/service/method;/admin",
    "/service/method|admin",
    "/service/method`admin`",
    # Empty and minimal paths
    "",
    "/",
    "//",
    "///",
    # Overly long paths (potential buffer issues)
    "/service/" + "a" * 10000,
    "/service/" + "../" * 1000 + "admin",
    # Encoded slashes
    "/service%2Fmethod%2Fadmin",
    "/service%2fmethod",
    # Backslash variants
    "/service\\method",
    "/service\\..\\admin",
    "/service/%5c%5c/admin",
    # Protocol-relative
    "//evil.com/service/method",
    # Semicolon path parameters
    "/service;param=value/method",
    "/service/method;jsessionid=abc123",
]


def normalize_path(path: str) -> str:
    """
    Simulate secure HTTP/2 path normalization and validation.
    Returns the normalized path or raises ValueError for invalid paths.
    """
    if not path:
        raise ValueError("Empty path is not allowed")

    # Decode percent-encoded characters (single decode only)
    try:
        decoded = urllib.parse.unquote(path, errors='strict')
    except Exception:
        raise ValueError(f"Invalid percent-encoding in path: {path!r}")

    # Check for null bytes after decoding
    if '\x00' in decoded or '\x00' in path:
        raise ValueError(f"Null byte detected in path: {path!r}")

    # Normalize the path (resolve . and ..)
    normalized = []
    for segment in decoded.split('/'):
        if segment == '..':
            if normalized:
                normalized.pop()
        elif segment == '.':
            continue
        else:
            normalized.append(segment)

    normalized_path = '/'.join(normalized)
    if not normalized_path.startswith('/'):
        normalized_path = '/' + normalized_path

    return normalized_path


def is_authorized_path(path: str, allowed_prefix: str = "/service/") -> bool:
    """
    Check if a path is authorized based on allowed prefix.
    This simulates the authorization check that must be secure.
    """
    if not path:
        return False

    # Decode percent-encoding before checking
    try:
        decoded_once = urllib.parse.unquote(path, errors='strict')
        # Check for double encoding by decoding again and comparing
        decoded_twice = urllib.parse.unquote(decoded_once, errors='strict')
    except Exception:
        return False

    # Null byte check
    if '\x00' in path or '\x00' in decoded_once or '\x00' in decoded_twice:
        return False

    # Normalize the path
    try:
        normalized = normalize_path(path)
    except ValueError:
        return False

    # The normalized path must start with the allowed prefix
    return normalized.startswith(allowed_prefix)


def extract_path_segments(path: str) -> list:
    """Extract and validate path segments."""
    if not path:
        return []

    try:
        decoded = urllib.parse.unquote(path, errors='strict')
    except Exception:
        return []

    segments = [s for s in decoded.split('/') if s and s not in ('.', '..')]
    return segments


@pytest.mark.parametrize("payload", ADVERSARIAL_PATHS)
def test_path_authorization_invariant(payload):
    """Invariant: Authorization decisions must be based on fully normalized paths,
    and adversarial path inputs must never bypass authorization boundaries.
    A path that resolves outside the allowed prefix must never be granted access."""

    allowed_prefix = "/service/"
    admin_paths = ["/admin", "/internal", "/secret", "/etc"]

    # Property 1: If authorization is granted, the normalized path must truly
    # start with the allowed prefix (no bypass via encoding/traversal)
    authorized = is_authorized_path(payload, allowed_prefix)

    if authorized:
        # If we say it's authorized, verify the normalized path is actually safe
        try:
            normalized = normalize_path(payload)
            assert normalized.startswith(allowed_prefix), (
                f"SECURITY VIOLATION: Path '{payload}' was authorized but "
                f"normalized to '{normalized}' which does not start with '{allowed_prefix}'"
            )
            # Ensure the normalized path doesn't escape to admin areas
            for admin_path in admin_paths:
                assert not normalized.startswith(admin_path), (
                    f"SECURITY VIOLATION: Path '{payload}' normalized to '{normalized}' "
                    f"which grants access to protected area '{admin_path}'"
                )
        except ValueError:
            pytest.fail(
                f"SECURITY VIOLATION: Path '{payload}' was authorized but "
                f"normalization raised an error - inconsistent validation"
            )

    # Property 2: Paths containing traversal sequences must not be authorized
    # to access admin/protected areas after normalization
    traversal_indicators = ['..', '%2e%2e', '%252e', '..%2f', '%2e%2e%2f']
    has_traversal = any(indicator in payload.lower() for indicator in traversal_indicators)

    if has_traversal:
        # A path with traversal sequences should either be rejected or
        # resolve to a safe location - never to an admin area
        try:
            normalized = normalize_path(payload)
            for admin_path in admin_paths:
                assert not normalized.startswith(admin_path), (
                    f"SECURITY VIOLATION: Path traversal in '{payload}' "
                    f"resolved to protected path '{normalized}'"
                )
        except ValueError:
            pass  # Rejection is acceptable for traversal paths

    # Property 3: Double-encoded paths must not bypass authorization
    try:
        single_decoded = urllib.parse.unquote(payload, errors='strict')
        double_decoded = urllib.parse.unquote(single_decoded, errors='strict')

        if single_decoded != double_decoded:
            # Double encoding detected - must not grant extra access
            auth_single = is_authorized_path(single_decoded, allowed_prefix)
            auth_double = is_authorized_path(double_decoded, allowed_prefix)
            auth_original = is_authorized_path(payload, allowed_prefix)

            # All three must agree on authorization to prevent bypass
            # If original is not authorized, neither decoded version should
            # grant access to admin areas
            if not auth_original:
                for admin_path in admin_paths:
                    try:
                        norm_single = normalize_path(single_decoded)
                        assert not norm_single.startswith(admin_path), (
                            f"SECURITY VIOLATION: Double-encoded path '{payload}' "
                            f"bypasses authorization via single decode to '{norm_single}'"
                        )
                    except ValueError:
                        pass

    except Exception:
        pass  # Encoding errors are acceptable rejections


@pytest.mark.parametrize("payload", ADVERSARIAL_PATHS)
def test_null_byte_path_rejection(payload):
    """Invariant: Paths containing null bytes (raw or encoded) must always be rejected."""
    null_variants = ['\x00', '%00', '%2500', '\u0000']

    has_null = any(variant in payload for variant in null_variants)

    if has_null:
        # Paths with null bytes must never be authorized
        authorized = is_authorized_path(payload, "/service/")
        assert not authorized, (
            f"SECURITY VIOLATION: Path containing null byte '{payload}' "
            f"was incorrectly authorized"
        )


@pytest.mark.parametrize("payload", ADVERSARIAL_PATHS)
def test_path_normalization_idempotency(payload):
    """Invariant: Path normalization must be idempotent - normalizing twice
    must produce the same result as normalizing once."""
    try:
        first_normalization = normalize_path(payload)
        second_normalization = normalize_path(first_normalization)

        assert first_normalization == second_normalization, (
            f"SECURITY VIOLATION: Path normalization is not idempotent for '{payload}'. "
            f"First: '{first_normalization}', Second: '{second_normalization}'. "
            f"This could indicate a normalization bypass vulnerability."
        )
    except ValueError:
        pass  # Rejection on first normalization is acceptable