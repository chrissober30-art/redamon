"""Regression: LLM-emitted priority synonyms (info/critical/urgent) used to
trigger a pydantic retry inside think_node because TodoItem.priority is a
strict Literal["high", "medium", "low"]. The before-validator now coerces
the common confusables so the parse succeeds on the first attempt.

Concrete incident: 2026-05-16 11:25:11 think step emitted
`priority: "info"` for a low-importance todo, costing one LLM round-trip
to recover.

Run (inside agent container):
    docker compose exec agent python -m pytest tests/test_state_priority_coercion.py -v
"""

from __future__ import annotations

import os
import sys
import unittest

_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)

from pydantic import ValidationError

from state import TodoItem, TodoItemUpdate


class PriorityCoercionTests(unittest.TestCase):
    def test_info_coerces_to_low_on_todoitem(self):
        item = TodoItem(description="x", priority="info")
        self.assertEqual(item.priority, "low")

    def test_critical_coerces_to_high_on_todoitem(self):
        item = TodoItem(description="x", priority="critical")
        self.assertEqual(item.priority, "high")

    def test_urgent_coerces_to_high_on_todoitem(self):
        item = TodoItem(description="x", priority="urgent")
        self.assertEqual(item.priority, "high")

    def test_canonical_values_pass_through_unchanged(self):
        for v in ("high", "medium", "low"):
            self.assertEqual(TodoItem(description="x", priority=v).priority, v)

    def test_case_insensitive(self):
        self.assertEqual(TodoItem(description="x", priority="INFO").priority, "low")
        self.assertEqual(TodoItem(description="x", priority="Critical").priority, "high")

    def test_whitespace_tolerated(self):
        self.assertEqual(TodoItem(description="x", priority="  info  ").priority, "low")

    def test_unknown_priority_still_rejected(self):
        # Coercion only handles known synonyms; truly invalid values still
        # surface as ValidationError so the LLM retry catches them.
        with self.assertRaises(ValidationError):
            TodoItem(description="x", priority="banana")

    def test_coercion_applies_to_todoitemupdate(self):
        # Same shape used by the LLM in `updated_todo_list` — must coerce
        # there too, otherwise the parse still fails (that was the actual
        # incident location: updated_todo_list.2.priority).
        upd = TodoItemUpdate(description="x", priority="info")
        self.assertEqual(upd.priority, "low")
        upd2 = TodoItemUpdate(description="x", priority="critical")
        self.assertEqual(upd2.priority, "high")


if __name__ == "__main__":
    unittest.main()
