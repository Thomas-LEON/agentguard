"""End-to-end tests for the Docker security boundary.

These tests require a running Docker daemon and are executed separately in CI.
"""

import shutil
import subprocess

import pytest

from agentguard.policy import SecurityPolicy
from agentguard.sandbox import DockerSandboxExecutor

pytestmark = pytest.mark.integration


@pytest.fixture
def docker_executor() -> DockerSandboxExecutor:
    """Skip locally when the Docker daemon is unavailable."""
    if shutil.which("docker") is None:
        pytest.skip("Docker CLI is not installed")
    daemon = subprocess.run(
        ["docker", "info"],
        capture_output=True,
        check=False,
    )
    if daemon.returncode != 0:
        pytest.skip("Docker daemon is not available")
    return DockerSandboxExecutor()


def test_docker_sandbox_executes_allowed_code(
    docker_executor: DockerSandboxExecutor,
) -> None:
    """The external runtime returns an allowed computation's result."""
    result = docker_executor.execute(
        "import math\nresult = math.sqrt(16)",
        SecurityPolicy(use_semantic_judge=False),
    )

    assert result.output == "4.0"


def test_docker_sandbox_has_no_network(
    docker_executor: DockerSandboxExecutor,
) -> None:
    """Network namespaces are disabled even for code that imports socket."""
    result = docker_executor.execute(
        "import socket\nsocket.create_connection(('1.1.1.1', 53), timeout=1)",
        SecurityPolicy(use_semantic_judge=False, execution_timeout=5),
    )

    assert "Execution error" in result.output
