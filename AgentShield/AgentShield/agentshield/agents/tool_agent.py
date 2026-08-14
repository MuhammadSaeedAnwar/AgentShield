"""The tool-using agent under test.

Loop (per user turn)
--------------------
1. Append the (optionally filtered) user turn.
2. Ask the model for a response, advertising the provisioned tools.
3. If the model requested tool calls:
   a. audit every call against the policy (always, even undefended);
   b. let the defense pipeline veto the call;
   c. execute it in the sandbox if it was not vetoed;
   d. filter the result (sanitise, wrap) and append it as a ``tool`` message;
   e. go back to 2 (up to ``max_steps``).
4. Otherwise the text is the answer for this turn: filter it, record it, move on
   to the next user turn.

The agent is deliberately *permissive by default*. With no defenses it executes
whatever the model asks for, as long as the tool exists in the session. That is
the vulnerable baseline the study measures against.
"""

from __future__ import annotations

import time
from typing import Any, Sequence

from ..defenses.base import DefenseEvent
from ..defenses.pipeline import DefensePipeline
from ..models.base import Message, ModelAdapter, ModelResponse, ToolCall
from ..tools.policy import PolicyState, ToolPolicy
from ..tools.registry import ToolCallRecord, ToolExecutor, ToolRegistry
from ..tools.sandbox import Sandbox
from .base import Episode
from .prompt import build_base_system_prompt, initial_messages

BLOCKED_TEMPLATE = (
    "error: the requested call to '{tool}' was blocked by the {defense} control ({detail}). "
    "Do not retry it. If the user needs this action, ask the user for explicit authorization first."
)


class ToolUsingAgent:
    """Runs one episode of a test case."""

    def __init__(
        self,
        model: ModelAdapter,
        registry: ToolRegistry,
        policy: ToolPolicy,
        defenses: DefensePipeline | None = None,
        *,
        max_steps: int = 6,
        tool_provisioning: str = "minimal",
    ) -> None:
        self.model = model
        self.registry = registry
        self.policy = policy
        self.defenses = defenses or DefensePipeline()
        self.max_steps = max_steps
        self.tool_provisioning = tool_provisioning

    # ------------------------------------------------------------------
    def run(self, case: Any, *, trial: int = 0, sandbox: Sandbox | None = None) -> Episode:
        started = time.perf_counter()
        sandbox = sandbox or Sandbox.from_case(case)
        executor = ToolExecutor(self.registry, sandbox)
        state = PolicyState()

        base_system = build_base_system_prompt(case, self.registry)
        system_outcome = self.defenses.build_system_prompt(base_system, case)
        messages = initial_messages(system_outcome.text)

        episode = Episode(
            case_id=getattr(case, "id", "unknown"),
            category=getattr(case, "category", "unknown"),
            trial=trial,
            model_name=self.model.model_name,
            provider=getattr(self.model, "provider", "unknown"),
            defenses=self.defenses.names,
            tool_provisioning=self.tool_provisioning,
            provisioned_tools=self.registry.names,
            system_prompt=system_outcome.text,
        )
        episode.defense_events.extend(system_outcome.events)

        specs = self.registry.specs()
        user_turns: Sequence[str] = getattr(case, "user_turns", []) or []

        try:
            for turn_index, raw_turn in enumerate(user_turns):
                # The *original* user text is what counts as trusted consent; the
                # filtered text is what the model sees.
                state.user_turns.append(raw_turn)
                turn_outcome = self.defenses.filter_user_turn(raw_turn, case)
                episode.defense_events.extend(turn_outcome.events)
                messages.append(Message(role="user", content=turn_outcome.text, trust="user"))
                episode.turns_used = turn_index + 1

                for step_index in range(self.max_steps):
                    response = self._call_model(case, messages, specs, trial, turn_index, step_index)
                    episode.steps_used += 1
                    if response.debug:
                        episode.model_debug.append(
                            {"turn": turn_index, "step": step_index, **response.debug}
                        )

                    if response.tool_calls:
                        messages.append(
                            Message(
                                role="assistant",
                                content=response.text or "",
                                tool_calls=list(response.tool_calls),
                                trust="trusted",
                            )
                        )
                        for call in response.tool_calls:
                            record = self._handle_call(
                                call, case, state, executor, episode, turn_index, step_index
                            )
                            content = record.result.content if record.result else "error: no result"
                            output_outcome = self.defenses.filter_tool_output(call.name, content, case)
                            episode.defense_events.extend(output_outcome.events)
                            messages.append(
                                Message(
                                    role="tool",
                                    content=output_outcome.text,
                                    name=call.name,
                                    tool_call_id=call.id,
                                    trust="untrusted",
                                )
                            )
                        continue

                    raw_text = response.text or ""
                    final_outcome = self.defenses.filter_final_output(raw_text, case, base_system)
                    episode.defense_events.extend(final_outcome.events)
                    episode.raw_assistant_texts.append(raw_text)
                    episode.assistant_texts.append(final_outcome.text)
                    messages.append(Message(role="assistant", content=final_outcome.text, trust="trusted"))
                    break
                else:
                    episode.truncated = True
                    episode.defense_events.append(
                        DefenseEvent(
                            "harness",
                            "loop",
                            "step_limit_reached",
                            f"turn {turn_index} hit max_steps={self.max_steps}",
                        )
                    )
        except Exception as exc:  # pragma: no cover - surfaced as an ERROR outcome
            episode.error = f"{type(exc).__name__}: {exc}"

        episode.messages = [m.to_dict() for m in messages]
        episode.sandbox_snapshot = sandbox.snapshot()
        episode.wall_time_s = time.perf_counter() - started
        return episode

    # ------------------------------------------------------------------
    def _call_model(
        self,
        case: Any,
        messages: list[Message],
        specs: list[Any],
        trial: int,
        turn_index: int,
        step_index: int,
    ) -> ModelResponse:
        context = {
            "case_id": getattr(case, "id", "unknown"),
            "trial": trial,
            "turn_index": turn_index,
            "step_index": step_index,
            # Consumed only by the mock adapter; API adapters ignore `context`,
            # so the benign-plan oracle never reaches a real model.
            "oracle": case.oracle() if hasattr(case, "oracle") else {},
        }
        if specs:
            return self.model.generate_with_tools(messages, specs, context=context)
        return self.model.generate(messages, context=context)

    def _handle_call(
        self,
        call: ToolCall,
        case: Any,
        state: PolicyState,
        executor: ToolExecutor,
        episode: Episode,
        turn_index: int,
        step_index: int,
    ) -> ToolCallRecord:
        verdict = self.policy.evaluate(call, state)
        blocked_by, events = self.defenses.gate_tool_call(call, verdict, state, case)
        episode.defense_events.extend(events)

        record = ToolCallRecord(
            call=call,
            verdict=verdict,
            executed=False,
            blocked_by=blocked_by,
            turn_index=turn_index,
            step_index=step_index,
        )

        if blocked_by:
            detail = "; ".join(v.detail for v in verdict.violations) or "policy violation"
            from ..tools.base import ToolResult  # local import avoids a cycle at module load

            record.result = ToolResult(
                ok=False,
                content=BLOCKED_TEMPLATE.format(tool=call.name, defense=blocked_by, detail=detail),
                error="blocked_by_defense",
                trust="trusted",
            )
        else:
            record.result = executor.execute(call)
            record.executed = bool(record.result.ok)
            state.call_counts[call.name] = state.call_counts.get(call.name, 0) + 1

        episode.tool_calls.append(record)
        return record
