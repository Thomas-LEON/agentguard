"""
Tests for Layer 1 — AST Static Validator.
"""

import pytest

from agentguard.exceptions import SecurityBlockedError
from agentguard.policy import SecurityPolicy
from agentguard.validators.ast_validator import ASTValidator


def test_allows_safe_code(default_policy: SecurityPolicy) -> None:
    """Code using only whitelisted modules should pass without exception."""
    code = "import math; result = math.sqrt(4)"
    ASTValidator(default_policy).validate(code)  # Should not raise


def test_blocks_forbidden_import(default_policy: SecurityPolicy) -> None:
    """Importing 'os' when not whitelisted should raise SecurityBlockedError."""
    code = "import os; os.system('ls')"
    with pytest.raises(SecurityBlockedError) as exc_info:
        ASTValidator(default_policy).validate(code)
    assert "os" in str(exc_info.value)
    assert "AST Validator" in str(exc_info.value)


def test_blocks_subprocess(default_policy: SecurityPolicy) -> None:
    """Importing 'subprocess' should be blocked."""
    code = "import subprocess; subprocess.run(['rm', '-rf', '/'])"
    with pytest.raises(SecurityBlockedError):
        ASTValidator(default_policy).validate(code)


def test_blocks_eval_call(default_policy: SecurityPolicy) -> None:
    """Direct use of eval() should be blocked regardless of imports."""
    code = "result = eval('__import__(\"os\").system(\"ls\")')"
    with pytest.raises(SecurityBlockedError) as exc_info:
        ASTValidator(default_policy).validate(code)
    assert "eval" in str(exc_info.value)


def test_blocks_exec_call(default_policy: SecurityPolicy) -> None:
    """Direct use of exec() should be blocked."""
    code = "exec('import os')"
    with pytest.raises(SecurityBlockedError) as exc_info:
        ASTValidator(default_policy).validate(code)
    assert "exec" in str(exc_info.value)


def test_blocks_from_import(default_policy: SecurityPolicy) -> None:
    """'from os import ...' style imports should also be blocked."""
    code = "from os import path"
    with pytest.raises(SecurityBlockedError):
        ASTValidator(default_policy).validate(code)


def test_invalid_syntax_raises_security_error(default_policy: SecurityPolicy) -> None:
    """Invalid syntax should raise SecurityBlockedError instead of SyntaxError."""
    code = "def broken(: pass"
    with pytest.raises(SecurityBlockedError) as exc_info:
        ASTValidator(default_policy).validate(code)
    assert "syntax" in str(exc_info.value).lower()


def test_allows_whitelisted_module(permissive_policy: SecurityPolicy) -> None:
    """Modules in the whitelist should pass without exception."""
    code = "import pandas as pd"
    ASTValidator(permissive_policy).validate(code)  # Should not raise


def test_blocks_getattr(default_policy: SecurityPolicy) -> None:
    """getattr() should be blocked — common sandbox escape vector."""
    code = "x = getattr(__builtins__, '__import__')"
    with pytest.raises(SecurityBlockedError) as exc_info:
        ASTValidator(default_policy).validate(code)
    assert "getattr" in str(exc_info.value)


def test_blocks_setattr(default_policy: SecurityPolicy) -> None:
    """setattr() should be blocked — attribute manipulation attack."""
    code = "setattr(obj, 'dangerous', True)"
    with pytest.raises(SecurityBlockedError) as exc_info:
        ASTValidator(default_policy).validate(code)
    assert "setattr" in str(exc_info.value)


def test_blocks_delattr(default_policy: SecurityPolicy) -> None:
    """delattr() should be blocked."""
    code = "delattr(obj, 'security_check')"
    with pytest.raises(SecurityBlockedError) as exc_info:
        ASTValidator(default_policy).validate(code)
    assert "delattr" in str(exc_info.value)


def test_blocks_globals_call(default_policy: SecurityPolicy) -> None:
    """globals() should be blocked — runtime introspection escape."""
    code = "g = globals()"
    with pytest.raises(SecurityBlockedError) as exc_info:
        ASTValidator(default_policy).validate(code)
    assert "globals" in str(exc_info.value)


def test_blocks_locals_call(default_policy: SecurityPolicy) -> None:
    """locals() should be blocked — runtime introspection escape."""
    code = "l = locals()"
    with pytest.raises(SecurityBlockedError) as exc_info:
        ASTValidator(default_policy).validate(code)
    assert "locals" in str(exc_info.value)
