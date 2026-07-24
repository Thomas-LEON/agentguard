from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import sys
import io
import contextlib
import traceback

from agentguard.policy import SecurityPolicy
from agentguard.exceptions import SecurityBlockedError

from dotenv import load_dotenv
load_dotenv()

app = FastAPI(title="AgentGuard Live Demo")

# Serve static files (HTML, CSS, JS)
app.mount("/static", StaticFiles(directory="demo/static"), name="static")


@app.get("/")
async def root():
    return FileResponse("demo/static/index.html")


class ExecuteRequest(BaseModel):
    code: str


class ExecuteResponse(BaseModel):
    status: str
    layer: str | None = None
    message: str
    output: str | None = None


# We use a relatively permissive policy for the demo but block `os.system`
demo_policy = SecurityPolicy(
    allowed_modules=["os", "math", "json", "sys", "socket"],
    denied_attributes={"os": ["system", "remove", "rmdir"]},
    use_semantic_judge=True,  # LLM ENABLED
)


@app.post("/api/execute", response_model=ExecuteResponse)
async def execute_code(request: ExecuteRequest):
    output_capture = io.StringIO()

    try:
        with contextlib.redirect_stdout(output_capture):
            # We call the secure_tool logic directly for the demo
            # to capture the AST validator and Execution layer behavior.
            from agentguard.validators.ast_validator import ASTValidator
            from agentguard.validators.network_filter import NetworkFilter

            # 1. AST Validation
            ASTValidator(demo_policy).validate(request.code)

            # 2. Network Validation
            NetworkFilter(demo_policy).validate(request.code)

            # 3. Semantic Judge (Real LLM connected)
            if demo_policy.use_semantic_judge:
                from agentguard.judges.gemini_judge import SemanticJudge
                from langchain_google_genai import ChatGoogleGenerativeAI
                import os

                api_key = os.environ.get(
                    "GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
                llm = ChatGoogleGenerativeAI(
                    model="gemini-3-flash-preview", google_api_key=api_key)
                SemanticJudge(llm).validate(request.code)

            # 3. Execution (simulate what LangChain tool does)
            allowed_builtins = {
                "print": print,
                "range": range,
                "len": len,
                "__build_class__": __build_class__,
                "__import__": __import__,  # AST Validator already secured the imports
            }
            safe_env = {"__builtins__": allowed_builtins}

            # Add allowed modules to safe_env for execution
            for mod in demo_policy.allowed_modules:
                safe_env[mod] = __import__(mod)

            exec(request.code, safe_env)

        return ExecuteResponse(
            status="allowed",
            message="Execution completed successfully.",
            output=output_capture.getvalue()
        )

    except SecurityBlockedError as e:
        return ExecuteResponse(
            status="blocked",
            layer=e.layer,
            message=str(e),
            output=output_capture.getvalue()
        )
    except Exception as e:
        return ExecuteResponse(
            status="error",
            layer="Execution Error",
            message=str(e),
            output=output_capture.getvalue() or traceback.format_exc()
        )
