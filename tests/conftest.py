"""
Pytest shared fixtures for the AgentGuard test suite.
"""

import pytest

from agentguard.policy import SecurityPolicy


@pytest.fixture
def default_policy() -> SecurityPolicy:
    """A minimal safe policy for testing purposes."""
    return SecurityPolicy(
        allowed_modules=["math", "json"],
        allowed_domains=[],
        use_semantic_judge=False,
    )


@pytest.fixture
def permissive_policy() -> SecurityPolicy:
    """A policy that allows more modules and a specific domain."""
    return SecurityPolicy(
        allowed_modules=["math", "json", "pandas", "re"],
        allowed_domains=["api.github.com"],
        use_semantic_judge=False,
    )


@pytest.fixture
def granular_policy() -> SecurityPolicy:
    """A policy that uses allowed_attributes and denied_attributes."""
    return SecurityPolicy(
        allowed_modules=["os", "sys"],
        allowed_attributes={"sys": ["version", "platform"]},
        denied_attributes={"os": ["system", "remove", "rmdir"]},
        use_semantic_judge=False,
    )
