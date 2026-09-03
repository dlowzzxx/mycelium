"""Payload persistence controls for ledger entries (issue #82)."""

from __future__ import annotations

from mycelium import ActionLedger, InMemoryLedgerStorage
from mycelium.transition import SideEffectClass, ToolTransitionBinding, derive_effect_id_for_call


def _binding() -> ToolTransitionBinding:
    return ToolTransitionBinding.for_tool(
        agent_id="test",
        policy_version="v1",
        side_effect_class=SideEffectClass.READ,
    )


def test_store_args_false_keeps_stable_effect_id() -> None:
    ledger = ActionLedger(storage=InMemoryLedgerStorage(), store_args=False)
    binding = _binding()
    args, kwargs = ("secret-payload",), {"api_key": "s3cret"}
    entry = ledger._new_inflight_entry("req-1", "tool", args, kwargs, binding=binding)
    assert entry.args == []
    assert entry.kwargs == {}
    assert entry.effect_id == derive_effect_id_for_call("tool", args, kwargs, binding)


def test_store_result_false_skips_replay_payload() -> None:
    ledger = ActionLedger(storage=InMemoryLedgerStorage(), store_result=False)
    claimed = ledger.claim("req-2", "tool", (), {})
    done = ledger.complete("req-2", {"sensitive": "data"}, _expected_fence=claimed.fence)
    assert done.result is None
    replayed = ledger.claim("req-2", "tool", (), {})
    assert replayed.result is None
