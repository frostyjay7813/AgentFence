"""
Structural assertions that the gate's deny-by-default posture is UNCHANGED.

The hardening on this branch adds stages (consumption, pre-effect receipt) and adds
keyword-only injection points. It must not weaken the dispatch path, and "we did not
weaken it" should be a test rather than a sentence in a pull request.

These checks are deliberately structural: they read ``enforce``'s own source and fail
if a future edit introduces an extra ALLOW exit, moves the ALLOW exit away from the end,
or drops a stage.

Copyright 2026 AgentFence contributors

Licensed under the Apache License, Version 2.0.
See LICENSE for details.
"""


from __future__ import annotations

import inspect
import re
import sys
import textwrap
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentfence.gate import enforce


def source() -> str:
    return textwrap.dedent(inspect.getsource(enforce))


class TestDenyByDefaultPosture:
    def test_exactly_one_allow_exit(self):
        """
        Exactly one ALLOW is ever produced, and it is the success path at the very end.

        It is bound to a name rather than returned inline (the outcome receipt still has
        to be linked to the pre-effect receipt), so this matches the decision argument
        rather than the ``return`` keyword.
        """
        allow_exits = re.findall(r'finish\(\s*"ALLOW"', source())
        assert len(allow_exits) == 1, (
            f"expected exactly one ALLOW construction in enforce(), found {len(allow_exits)}"
        )

    def test_many_deny_exits_remain(self):
        """The failure surface stays explicit rather than collapsing into one catch-all."""
        deny_exits = re.findall(r'finish\(\s*"DENY"', source())
        assert len(deny_exits) >= 15, f"only {len(deny_exits)} DENY exits found"

    def test_allow_exit_is_the_last_decision(self):
        src = source()
        allow_at = re.search(r'finish\(\s*"ALLOW"', src).start()
        last_deny = max(m.start() for m in re.finditer(r'finish\(\s*"DENY"', src))
        assert allow_at > last_deny, "an ALLOW construction appears before a DENY construction"

    def test_every_stage_label_is_present(self):
        """
        Every verification stage still has its own labelled exit.

        Removing a stage usually looks like deleting its ``finish(..., "<n>-<name>")``
        call. This catches that.
        """
        src = source()
        expected = [
            "0-schema",
            "1-authorization",
            "2-integrity",
            "3-registries",
            "4-validity",
            "5-bindings",
            "6-policy-lookup",
            "7-policy-effect",
            "8-approval",
            "9-policy-scope",
            "10-capability",
            "11-consume",
            "12-execute",
        ]
        missing = [s for s in expected if f'"{s}"' not in src]
        assert not missing, f"stages missing from the gate: {missing}"

    def test_no_bypass_parameters_were_added(self):
        params = set(inspect.signature(enforce).parameters)
        forbidden = {
            "skip_verify", "bypass", "debug", "allow_all", "trust", "force",
            "skip_consume", "skip_receipt", "unsafe", "no_auth", "anonymous",
        }
        assert not (params & forbidden), f"gate exposes bypass surface: {params & forbidden}"

    def test_injection_parameters_default_to_safe_resolution(self):
        """The new injection points default to None, i.e. resolve from configuration."""
        sig = inspect.signature(enforce)
        for name in ("consume_store", "receipt_chain", "receipt_key", "clock_skew_ms"):
            assert sig.parameters[name].default is None, (
                f"{name} must default to None (resolve from config), not to a permissive value"
            )

    def test_authorization_type_none_is_not_a_default_anywhere(self):
        """No module in the package offers NONE as an accepted authorization type."""
        package = Path(__file__).resolve().parents[1] / "agentfence"
        offenders = []
        for path in package.glob("*.py"):
            text = path.read_text(encoding="utf-8")
            if "AuthorizationType" in text and "NONE" in text:
                # The only permitted occurrence is the explicit rejection.
                if "AUTHORIZATION_TYPE_NONE_REJECTED" not in text:
                    offenders.append(path.name)
        assert offenders == [], f"AuthorizationType NONE handled without rejection: {offenders}"
