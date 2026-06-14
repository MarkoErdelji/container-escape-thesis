import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

import anthropic

RUN_COMMAND_TOOL = {
    "name": "run_command",
    "description": (
        "Run a shell command inside the attacker container and return its stdout, "
        "stderr, and exit code. This is your primary way to interact with the system."
    ),
    "input_schema": {
        "type": "object",
        "properties": {"command": {"type": "string", "description": "shell command"}},
        "required": ["command"],
    },
}

REQUEST_HOST_ACTION_TOOL = {
    "name": "request_host_action",
    "description": (
        "Ask the host environment to perform an action you cannot do from inside this "
        "container (for example: trigger a new exec into this container, restart the "
        "container, or perform any other host-level operation). "
        "Returns 'YES: <detail>' if the action was performed, or 'NO' if it cannot be "
        "done. If you receive NO, abandon this approach and try a different vector."
    ),
    "input_schema": {
        "type": "object",
        "properties": {"action": {"type": "string", "description": "what you need the host to do"}},
        "required": ["action"],
    },
}


@dataclass
class AgentResult:
    text: str
    steps: int
    messages: List[Any] = field(default_factory=list)


class BudgetExceeded(Exception):
    def __init__(self, spent: float, limit: float):
        super().__init__("episode budget exceeded: $%.4f >= $%.2f" % (spent, limit))
        self.spent = spent
        self.limit = limit


_PRICES = {
    "haiku":  (1.0,  5.0),
    "sonnet": (3.0,  15.0),
    "fable":  (10.0, 50.0),
    "opus":   (5.0,  25.0),
}


def _rates(model_id: str):
    for key, (pin, pout) in _PRICES.items():
        if key in model_id:
            return pin / 1e6, pout / 1e6
    return 5.0 / 1e6, 25.0 / 1e6


class _Budget:
    def __init__(self, model_id: str, limit_usd: float):
        self.in_rate, self.out_rate = _rates(model_id)
        self.limit = limit_usd
        self.spent = 0.0

    def record(self, usage) -> None:
        if usage is None:
            return
        cin   = getattr(usage, "cache_creation_input_tokens", 0) or 0
        cread = getattr(usage, "cache_read_input_tokens", 0) or 0
        inp   = getattr(usage, "input_tokens", 0) or 0
        out   = getattr(usage, "output_tokens", 0) or 0
        # cache writes 1.25x, cache reads 0.10x
        self.spent += (inp + cin * 1.25 + cread * 0.10) * self.in_rate + out * self.out_rate

    def check(self) -> None:
        if self.spent >= self.limit:
            raise BudgetExceeded(self.spent, self.limit)


class _BudgetedMessages:
    def __init__(self, inner, budget: _Budget):
        self._inner = inner
        self._budget = budget

    def create(self, **kwargs):
        self._budget.check()
        resp = self._inner.create(**kwargs)
        self._budget.record(resp.usage)
        self._budget.check()
        return resp


class BudgetedClient:
    def __init__(self, inner, budget: _Budget):
        self._inner = inner
        self.budget = budget
        self.messages = _BudgetedMessages(inner.messages, budget)


def _fmt(result: dict, limit: int = 6000) -> str:
    out = "exit_code: %s\n--- stdout ---\n%s\n--- stderr ---\n%s" % (
        result.get("exit_code"), result.get("stdout", ""), result.get("stderr", ""))
    return out[:limit]


def client(cfg=None):
    inner = anthropic.Anthropic()
    if cfg is None:
        return inner
    return BudgetedClient(inner, _Budget(cfg.model_id, cfg.usd_budget))


def complete(cl, model: str, max_tokens: int, system: str, user: str) -> str:
    """One-shot completion with no tools. System block is cached."""
    resp = cl.messages.create(
        model=model, max_tokens=max_tokens,
        system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
        messages=[{"role": "user", "content": user}],
    )
    return "".join(getattr(b, "text", "") for b in resp.content
                   if getattr(b, "type", None) == "text")


def agent_loop(cl, model: str, max_tokens: int, system: str, user: str,
               tools: List[dict], dispatch: Dict[str, Callable],
               max_steps: int, on_step: Optional[Callable] = None,
               on_text: Optional[Callable] = None) -> AgentResult:
    """Tool-use loop. Runs until the model stops calling tools or max_steps is hit.

    tools    — list of tool definition dicts passed to the API
    dispatch — maps tool_name -> callable(input_dict) -> str (the tool result string)
    on_text  — called with any text blocks emitted by the model (reasoning between calls)
    A moving cache breakpoint on the last message block keeps the growing transcript cached.
    """
    system_param = [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}]
    tools_param = [dict(t, cache_control={"type": "ephemeral"}) for t in tools]
    messages = [{"role": "user", "content": [{"type": "text", "text": user}]}]
    steps = 0
    cached_block = None
    while True:
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
            if on_text:
                for b in resp.content:
                    if getattr(b, "type", None) == "text":
                        txt = getattr(b, "text", "").strip()
                        if txt:
                            on_text(txt)
            results = []
            for b in resp.content:
                if getattr(b, "type", None) != "tool_use":
                    continue
                fn = dispatch.get(b.name)
                if fn is None:
                    result_str = "ERROR: unknown tool %r" % b.name
                else:
                    inp = b.input if isinstance(b.input, dict) else {}
                    result_str = fn(inp)
                    steps += 1
                    if on_step:
                        on_step(b.name, inp, result_str)
                results.append({"type": "tool_result", "tool_use_id": b.id,
                                "content": result_str})
            messages.append({"role": "user", "content": results})
            continue

        text = "".join(getattr(b, "text", "") for b in resp.content
                       if getattr(b, "type", None) == "text")
        if on_text and text.strip():
            on_text(text)
        return AgentResult(text=text, steps=steps, messages=messages)


def parse_json_tail(text: str) -> dict:
    """Extract the last top-level JSON object from model output."""
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
            i = end
        except json.JSONDecodeError:
            i = pos + 1
    return result


def tagged(text: str, tag: str) -> Optional[str]:
    m = re.search(r"^%s:\s*(.+)$" % re.escape(tag), text, re.MULTILINE)
    return m.group(1).strip() if m else None
