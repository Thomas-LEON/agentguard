"""
Example: Threat Intelligence Agent with AgentGuard.

A more advanced demo: an agent that analyses security logs and threat data,
protected by AgentGuard against data exfiltration and destructive operations.

This example shows how AgentGuard protects an agent that processes
sensitive threat intelligence data — preventing it from sending data
to external servers or deleting evidence.

Requirements:
    pip install agentguard langchain langchain-google-genai

Usage:
    export GEMINI_API_KEY="your_api_key_here"
    python examples/threat_intel_demo.py
"""

import os

from dotenv import load_dotenv
from langchain.agents import AgentExecutor, create_react_agent
from langchain_core.prompts import PromptTemplate
from langchain_google_genai import ChatGoogleGenerativeAI

from agentguard import SafePythonREPLTool, SecurityPolicy

load_dotenv()

# ── Security Policy: tailored for threat analysis ────────────────────────────
# The agent can use data analysis libraries but cannot access the network
# or the file system — it can only process data passed to it in-memory.
threat_policy = SecurityPolicy(
    allowed_modules=[
        "json",
        "re",
        "datetime",
        "collections",
        "math",
        "statistics",
    ],
    allowed_domains=[],  # Zero network access — no data exfiltration possible
    use_semantic_judge=True,
    execution_timeout=15,
)

# ── LLM & Tool Setup ─────────────────────────────────────────────────────────
llm = ChatGoogleGenerativeAI(
    model="gemini-2.0-flash",
    google_api_key=os.getenv("GEMINI_API_KEY"),
    transport="rest",  # Force REST API to avoid gRPC SSL certificate issues on Windows
)

safe_repl = SafePythonREPLTool(
    policy=threat_policy,
    judge_llm=llm,
)

# ── Simulated Threat Data ─────────────────────────────────────────────────────
SAMPLE_LOGS = """
[2026-07-21 10:14:32] ALERT src=192.168.1.105 dst=45.33.32.156 proto=TCP port=4444 action=BLOCKED rule=C2_CALLBACK
[2026-07-21 10:14:33] ALERT src=192.168.1.105 dst=45.33.32.156 proto=TCP port=4444 action=BLOCKED rule=C2_CALLBACK
[2026-07-21 10:15:01] ALERT src=10.0.0.42 dst=198.51.100.1 proto=UDP port=53 action=ALLOWED rule=DNS_QUERY
[2026-07-21 10:15:12] ALERT src=192.168.1.105 dst=203.0.113.50 proto=TCP port=443 action=BLOCKED rule=DATA_EXFIL
[2026-07-21 10:15:45] ALERT src=192.168.1.200 dst=45.33.32.156 proto=TCP port=4444 action=BLOCKED rule=C2_CALLBACK
[2026-07-21 10:16:02] ALERT src=10.0.0.42 dst=8.8.8.8 proto=UDP port=53 action=ALLOWED rule=DNS_QUERY
[2026-07-21 10:16:30] ALERT src=192.168.1.105 dst=45.33.32.156 proto=TCP port=4444 action=BLOCKED rule=C2_CALLBACK
[2026-07-21 10:17:00] ALERT src=192.168.1.105 dst=203.0.113.50 proto=TCP port=443 action=BLOCKED rule=DATA_EXFIL
""".strip()

# ── Agent Prompt ──────────────────────────────────────────────────────────────
AGENT_PROMPT = PromptTemplate.from_template("""You are a cybersecurity threat analyst.
You have access to a secure Python interpreter to process security log data.
You MUST use the provided log data — do NOT attempt to read files or access the network.

Available log data (already loaded as a string variable):
```
{logs}
```

Tools available:
{tools}

Tool names: {tool_names}

Use the following format:

Question: the input question you must answer
Thought: you should always think about what to do
Action: the action to take, should be one of [{tool_names}]
Action Input: the input to the action
Observation: the result of the action
... (this Thought/Action/Action Input/Observation can repeat N times)
Thought: I now know the final answer
Final Answer: the final answer to the original input question

Begin!

Question: {input}
Thought:{agent_scratchpad}""")

agent = create_react_agent(llm=llm, tools=[safe_repl], prompt=AGENT_PROMPT)
executor = AgentExecutor(
    agent=agent,
    tools=[safe_repl],
    verbose=True,
    handle_parsing_errors=True,
    max_iterations=5,
)

# ── Run ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("🛡️  AgentGuard Demo — Threat Intelligence Agent")
    print("=" * 60)

    analysis_request = (
        "Analyse these firewall logs. "
        "Count the unique source IPs that triggered BLOCKED alerts, "
        "identify the most contacted suspicious destination IP, "
        "and determine the most common rule triggered. "
        "Present the results as a structured JSON summary."
    )

    result = executor.invoke({
        "input": analysis_request,
        "logs": SAMPLE_LOGS,
    })

    print("\n" + "=" * 60)
    print("📊 Analysis Result:")
    print("=" * 60)
    print(result["output"])
