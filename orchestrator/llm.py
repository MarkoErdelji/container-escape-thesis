"""Anthropic client glue: the run_command tool schema and a tool-use agent loop.

Shared by every stage so the pipeline structure (not bespoke per-stage plumbing) is what
varies. Requires ANTHROPIC_API_KEY in the environment.
"""
import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, List, Optional

import anthropic

RUN_COMMAND_TOOL = {
    "name": "run_command",
    "description": (
        "Run a shell command inside the attacker container and return its stdout, "
        "stderr, and exit code. This is your only way to interact with the system."
    ),
    "input_schema": {
        "type": "object",
        "properties": {"command": {"type": "string", "description": "shell command"}},
        "required": ["command"],
    },
}

# Used by the evaluator's research phase — runs on the orchestrator host (the VM),
# NOT inside the attacker container. Intended for CVE lookups, GitHub searches, etc.
HOST_RUN_TOOL = {
    "name": "host_run",
    "description": (
        "Run a shell command on the lab host (the VM) for RESEARCH ONLY — curl CVE "
        "databases, search GitHub for PoC repos, look up version ranges. Read-only "
        "information gathering; do not modify files or start background processes."
    ),
    "input_schema": {
        "type": "object",
        "properties": {"command": {"type": "string", "description": "shell command (curl/grep/cat)"}},
        "required": ["command"],
    },
}


@dataclass
class AgentResult:
    text: str
    steps: int
    messages: List[Any] = field(default_factory=list)


class BudgetExceeded(Exception):
    """Raised when an episode's estimated API spend crosses cfg.usd_budget."""

    def __init__(self, spent: float, limit: float):
        super().__init__("episode budget exceeded: $%.4f >= $%.2f" % (spent, limit))
        self.spent = spent
        self.limit = limit


# USD per million tokens (input, output), keyed by a substring of the model id.
_PRICES = {
    "haiku": (1.0, 5.0),
    "sonnet": (3.0, 15.0),
    "fable": (10.0, 50.0),
    "opus": (5.0, 25.0),
}


def _rates(model_id: str):
    for key, (pin, pout) in _PRICES.items():
        if key in model_id:
            return pin / 1e6, pout / 1e6
    return 5.0 / 1e6, 25.0 / 1e6  # conservative default (opus-tier) for unknown ids


class _Budget:
    """Accumulates estimated USD spend across every messages.create in an episode."""

    def __init__(self, model_id: str, limit_usd: float):
        self.in_rate, self.out_rate = _rates(model_id)
        self.limit = limit_usd
        self.spent = 0.0

    def record(self, usage) -> None:
        if usage is None:
            return
        cin = getattr(usage, "cache_creation_input_tokens", 0) or 0
        cread = getattr(usage, "cache_read_input_tokens", 0) or 0
        inp = getattr(usage, "input_tokens", 0) or 0
        out = getattr(usage, "output_tokens", 0) or 0
        # Anthropic cache pricing: cache writes cost 1.25x input, cache reads 0.10x input.
        # Pricing them correctly is what lets caching actually lower episode spend.
        self.spent += (inp + cin * 1.25 + cread * 0.10) * self.in_rate + out * self.out_rate

    def check(self) -> None:
        if self.spent >= self.limit:
            raise BudgetExceeded(self.spent, self.limit)


class _BudgetedMessages:
    def __init__(self, inner, budget: _Budget):
        self._inner = inner
        self._budget = budget

    def create(self, **kwargs):
        self._budget.check()              # don't start a call we can't afford
        resp = self._inner.create(**kwargs)
        self._budget.record(resp.usage)
        self._budget.check()              # stop if this call pushed us over
        return resp


class BudgetedClient:
    """Drop-in for anthropic.Anthropic that enforces a per-episode USD cap."""

    def __init__(self, inner, budget: _Budget):
        self._inner = inner
        self.budget = budget
        self.messages = _BudgetedMessages(inner.messages, budget)


def _fmt(result: dict, limit: int = 6000) -> str:
    out = "exit_code: %s\n--- stdout ---\n%s\n--- stderr ---\n%s" % (
        result.get("exit_code"), result.get("stdout", ""), result.get("stderr", ""))
    return out[:limit]


def client(cfg=None):
    """Return an Anthropic client. With a cfg, wrap it so each episode hard-stops
    at cfg.usd_budget (estimated from token usage and the model's per-token rates)."""
    inner = anthropic.Anthropic()
    if cfg is None:
        return inner
    return BudgetedClient(inner, _Budget(cfg.model_id, cfg.usd_budget))


def complete(cl, model: str, max_tokens: int, system: str, user: str) -> str:
    """One-shot completion with no tools (used by the Evaluator). The (static) system block
    is cached so repeated evaluator calls — replans, and across a batch within the cache TTL
    — reuse it cheaply."""
    resp = cl.messages.create(
        model=model, max_tokens=max_tokens,
        system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
        messages=[{"role": "user", "content": user}],
    )
    return "".join(getattr(b, "text", "") for b in resp.content
                   if getattr(b, "type", None) == "text")


def agent_loop(cl, model: str, max_tokens: int, system: str, user: str,
               runner, max_steps: int,
               on_step: Optional[Callable] = None,
               tool: Optional[dict] = None) -> AgentResult:
    """Tool-use loop. The model proposes tool calls; we execute and feed back.

    `tool` defaults to RUN_COMMAND_TOOL (attacker container). Pass HOST_RUN_TOOL +
    a HostRunner to give the evaluator a research loop against the VM host instead.

    Once the step budget is hit we drop the tool so the model must conclude in text.

    Prompt caching: the (static) system prompt and tool schema are cached, and a moving cache
    breakpoint is kept on the latest turn so the growing transcript prefix is cached too —
    cache reads are ~10x cheaper, so a long multi-step episode reprocesses its history at a
    fraction of the cost (and `_Budget` prices the cache tokens accordingly).
    """
    active_tool = tool or RUN_COMMAND_TOOL
    tool_name = active_tool["name"]
    system_param = [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}]
    tools_param = [dict(active_tool, cache_control={"type": "ephemeral"})]
    messages = [{"role": "user", "content": [{"type": "text", "text": user}]}]
    steps = 0
    cached_block = None  # the message block currently holding the moving cache breakpoint
    while True:
        # Move the conversation cache breakpoint onto the last block of the latest message,
        # so everything before it (system, tools, all prior turns) is served from cache.
        if cached_block is not None:
            cached_block.pop("cache_control", None)
        tail = messages[-1].get("content")
        if isinstance(tail, list) and tail and isinstance(tail[-1], dict):
            tail[-1]["cache_control"] = {"type": "ephemeral"}
            cached_block = tail[-1]
        kwargs = dict(model=model, max_tokens=max_tokens, system=system_param, messages=messages)
        if steps < max_steps:
            kwargs["tools"] = tools_param
        resp = cl.messages.create(**kwargs)
        messages.append({"role": "assistant", "content": resp.content})

        if resp.stop_reason == "tool_use":
            results = []
            for b in resp.content:
                if getattr(b, "type", None) == "tool_use" and b.name == tool_name:
                    cmd = b.input.get("command", "") if isinstance(b.input, dict) else ""
                    res = runner.run(cmd)
                    steps += 1
                    if on_step:
                        on_step(cmd, res)
                    results.append({"type": "tool_result", "tool_use_id": b.id,
                                    "content": _fmt(res)})
            messages.append({"role": "user", "content": results})
            continue

        text = "".join(getattr(b, "text", "") for b in resp.content
                       if getattr(b, "type", None) == "text")
        return AgentResult(text=text, steps=steps, messages=messages)


def parse_json_tail(text: str) -> dict:
    """Extract the last top-level JSON object from model output. Handles arbitrary nesting.

    Uses raw_decode so deeply nested structures (ranked items with sub-dicts, escape_chain
    items with curly-brace text, etc.) parse correctly. Jumps past each parsed object so
    only top-level objects are considered; returns the last one found.
    """
    decoder = json.JSONDecoder()
    result: dict = {}
    i = 0
    while i < len(text):
        pos = text.find("{", i)
        if pos == -1:
            break
        try:
            obj, end = decoder.raw_decode(text, pos)
            if isinstance(obj, dict):
                result = obj
            i = end  # jump past the whole parsed object — skips inner {…} blocks
        except json.JSONDecodeError:
            i = pos + 1
    return result


def tagged(text: str, tag: str) -> Optional[str]:
    """Return the value after a 'TAG: value' line, if present."""
    m = re.search(r"^%s:\s*(.+)$" % re.escape(tag), text, re.MULTILINE)
    return m.group(1).strip() if m else None
