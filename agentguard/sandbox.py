"""External execution backends for AgentGuard.

Python-level restrictions are not a security boundary. This module executes
generated code only in an external runtime and fails closed if it is unavailable.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Protocol

from agentguard.policy import SecurityPolicy


class SandboxUnavailableError(RuntimeError):
    """Raised when no secure external execution runtime is available."""


@dataclass(frozen=True)
class SandboxResult:
    """Normalized output returned by an external sandbox."""

    output: str
    timed_out: bool = False
    output_limit_exceeded: bool = False


class SandboxExecutor(Protocol):
    """Interface implemented by external code-execution backends."""

    def execute(self, code: str, policy: SecurityPolicy) -> SandboxResult:
        """Execute code outside the AgentGuard process."""


_RUNNER = """
import contextlib
import io
import json
import traceback

source = input_stream.read()
captured_stdout = io.StringIO()
namespace = {"__name__": "__agentguard__"}

try:
    with contextlib.redirect_stdout(captured_stdout):
        exec(compile(source, "<agentguard>", "exec"), namespace, namespace)
    result = namespace.get("result")
    response = {
        "status": "ok",
        "stdout": captured_stdout.getvalue(),
        "result": None if result is None else str(result),
    }
except BaseException:
    response = {
        "status": "error",
        "stdout": captured_stdout.getvalue(),
        "error": traceback.format_exc(limit=3),
    }

output_stream.write("__AGENTGUARD_RESULT__" + json.dumps(response) + "\\n")
"""


class DockerSandboxExecutor:
    """Run code in a short-lived Docker container with restrictive defaults.

    The container has no host mounts or network, a read-only root filesystem, no
    Linux capabilities, a non-root user and CPU, memory and PID limits. Docker is
    part of the trusted computing base; production deployments should pin image to
    a reviewed digest.
    """

    def __init__(
        self,
        image: str = "python:3.11-alpine",
        docker_binary: str = "docker",
    ) -> None:
        self.image = image
        self.docker_binary = docker_binary

    def execute(self, code: str, policy: SecurityPolicy) -> SandboxResult:
        """Execute code in Docker, failing closed if the runtime is absent."""
        source = code.encode("utf-8")
        if len(source) > policy.max_code_bytes:
            return SandboxResult(
                output=(
                    "[AgentGuard] BLOCKED - Code exceeds the "
                    f"{policy.max_code_bytes}-byte execution limit."
                )
            )

        with tempfile.TemporaryDirectory(prefix="agentguard-sandbox-") as temp_dir:
            cidfile = Path(temp_dir) / "container-id"
            try:
                process = subprocess.Popen(
                    self._command(policy, cidfile),
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
            except FileNotFoundError as exc:
                raise SandboxUnavailableError(
                    "Docker is required for secure execution but was not found. "
                    "Install Docker or configure another external SandboxExecutor."
                ) from exc

            stdout, stderr, timed_out, output_limit_exceeded = self._communicate(
                process, source, policy, cidfile
            )
        if timed_out:
            return SandboxResult(
                output=(
                    "[AgentGuard] TIMEOUT - The sandboxed process was terminated after "
                    f"{policy.execution_timeout}s."
                ),
                timed_out=True,
            )
        if output_limit_exceeded:
            return SandboxResult(
                output=(
                    "[AgentGuard] BLOCKED - The sandboxed process exceeded the "
                    f"{policy.max_output_bytes}-byte output limit and was terminated."
                ),
                output_limit_exceeded=True,
            )
        if process.returncode != 0:
            detail = stderr.decode("utf-8", errors="replace").strip()
            return SandboxResult(output=f"Sandbox execution error: {detail}")

        return SandboxResult(output=self._format_response(stdout, stderr))

    def _command(
        self, policy: SecurityPolicy, cidfile: Path | None = None
    ) -> list[str]:
        """Build a Docker command without invoking a shell."""
        command = [
            self.docker_binary,
            "run",
            "--rm",
            "--interactive",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--pids-limit",
            str(policy.pids_limit),
            "--memory",
            f"{policy.memory_limit_mb}m",
            "--memory-swap",
            f"{policy.memory_limit_mb}m",
            "--cpus",
            str(policy.cpu_limit),
            "--user",
            "65534:65534",
            "--workdir",
            "/tmp",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=16m",
            "--env",
            "PYTHONDONTWRITEBYTECODE=1",
            "--env",
            "PYTHONUNBUFFERED=1",
            self.image,
            "python",
            "-I",
            "-S",
            "-c",
            "import sys; input_stream=sys.stdin; output_stream=sys.stdout; " + _RUNNER,
        ]
        if cidfile is not None:
            command[3:3] = ["--cidfile", str(cidfile)]
        return command

    def _communicate(
        self,
        process: subprocess.Popen[bytes],
        source: bytes,
        policy: SecurityPolicy,
        cidfile: Path,
    ) -> tuple[bytes, bytes, bool, bool]:
        """Stream output with a hard host-side cap, terminating on violation."""
        stdout = bytearray()
        stderr = bytearray()
        output_limit_exceeded = threading.Event()
        output_lock = threading.Lock()
        output_size = 0

        def drain(stream: BinaryIO, destination: bytearray) -> None:
            nonlocal output_size
            while chunk := stream.read(4096):
                with output_lock:
                    if output_size + len(chunk) > policy.max_output_bytes:
                        output_limit_exceeded.set()
                        self._terminate(process, cidfile)
                        return
                    output_size += len(chunk)
                    destination.extend(chunk)

        assert process.stdin is not None
        assert process.stdout is not None
        assert process.stderr is not None
        writer = threading.Thread(target=_write_source, args=(process.stdin, source))
        stdout_reader = threading.Thread(target=drain, args=(process.stdout, stdout))
        stderr_reader = threading.Thread(target=drain, args=(process.stderr, stderr))
        for thread in (writer, stdout_reader, stderr_reader):
            thread.start()

        timed_out = False
        try:
            process.wait(timeout=policy.execution_timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            self._terminate(process, cidfile)

        for thread in (writer, stdout_reader, stderr_reader):
            thread.join()
        return bytes(stdout), bytes(stderr), timed_out, output_limit_exceeded.is_set()

    def _terminate(self, process: subprocess.Popen[bytes], cidfile: Path) -> None:
        """Terminate both the Docker client and its container, if it was created."""
        if process.poll() is None:
            process.kill()

        for _ in range(10):
            try:
                container_id = cidfile.read_text(encoding="utf-8").strip()
            except FileNotFoundError:
                time.sleep(0.05)
                continue
            if container_id:
                subprocess.run(
                    [self.docker_binary, "kill", container_id],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
            return

    @staticmethod
    def _format_response(stdout: bytes, stderr: bytes) -> str:
        """Return captured output from the runner's final structured response."""
        text = stdout.decode("utf-8", errors="replace")
        marker = "__AGENTGUARD_RESULT__"
        response_line = next(
            (line for line in reversed(text.splitlines()) if line.startswith(marker)),
            None,
        )
        if response_line is None:
            detail = stderr.decode("utf-8", errors="replace").strip()
            return f"Sandbox execution error: {detail or 'invalid sandbox response'}"

        try:
            response = json.loads(response_line.removeprefix(marker))
        except json.JSONDecodeError:
            return "Sandbox execution error: invalid structured response."

        parts: list[str] = []
        captured = response.get("stdout", "").strip()
        if captured:
            parts.append(captured)
        if response.get("status") == "error":
            parts.append(f"Execution error: {response.get('error', 'unknown error')}")
        elif response.get("result") is not None:
            parts.append(str(response["result"]))
        if parts:
            return "\n".join(parts)
        return "Code executed successfully (no output produced)."


def _write_source(stream: BinaryIO, source: bytes) -> None:
    """Write generated code to the container without blocking the caller."""
    try:
        stream.write(source)
    except BrokenPipeError:
        pass
    finally:
        stream.close()
