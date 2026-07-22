"""Tests for the Docker sandbox command and response parsing."""

import json
from pathlib import Path

from agentguard.policy import SecurityPolicy
from agentguard.sandbox import DockerSandboxExecutor


def test_docker_command_enforces_host_isolation_controls() -> None:
    """The default Docker command must include the mandatory confinement flags."""
    executor = DockerSandboxExecutor(image="registry.example/agentguard@sha256:abc")
    command = executor._command(
        SecurityPolicy(use_semantic_judge=False)
    )

    assert "--network" in command
    assert command[command.index("--network") + 1] == "none"
    assert "--read-only" in command
    assert command[command.index("--cap-drop") + 1] == "ALL"
    assert command[command.index("--user") + 1] == "65534:65534"
    assert command[command.index("--pids-limit") + 1] == "64"
    assert "--tmpfs" in command
    assert "--rm" in command


def test_docker_command_does_not_mount_host_paths() -> None:
    """Generated code must never receive a host bind mount by default."""
    command = DockerSandboxExecutor()._command(SecurityPolicy(use_semantic_judge=False))

    assert "--volume" not in command
    assert "--mount" not in command


def test_docker_command_records_container_id_for_forced_cleanup() -> None:
    """Timeout handling needs the container ID even if its client is killed."""
    cidfile = Path("/tmp/agentguard-test-container-id")
    command = DockerSandboxExecutor()._command(
        SecurityPolicy(use_semantic_judge=False), cidfile
    )

    assert command[command.index("--cidfile") + 1] == str(cidfile)


def test_successful_runner_response_returns_stdout_and_result() -> None:
    """The structured runner response is rendered for the LangChain agent."""
    response = {"status": "ok", "stdout": "step complete\n", "result": "42"}
    stdout = f"__AGENTGUARD_RESULT__{json.dumps(response)}\n".encode()

    output = DockerSandboxExecutor._format_response(stdout, b"")

    assert output == "step complete\n42"


def test_runner_error_is_returned_without_reexecution() -> None:
    """The host returns an external failure rather than trying local execution."""
    response = {"status": "error", "stdout": "", "error": "Traceback: boom"}
    stdout = f"__AGENTGUARD_RESULT__{json.dumps(response)}\n".encode()

    output = DockerSandboxExecutor._format_response(stdout, b"")

    assert "Execution error" in output
    assert "boom" in output


def test_oversized_source_is_blocked_before_docker_is_started() -> None:
    """Source-size limits protect the host from oversized stdin writes."""
    policy = SecurityPolicy(use_semantic_judge=False, max_code_bytes=1024)

    result = DockerSandboxExecutor().execute("x" * 1025, policy)

    assert "BLOCKED" in result.output
