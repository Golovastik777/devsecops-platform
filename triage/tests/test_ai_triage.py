import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ai_triage  # noqa: E402


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "main.py").write_text("import subprocess\nsubprocess.run(cmd, shell=True)\n")
    (tmp_path / ".env").write_text("TOKEN=secret\n")
    return tmp_path


FINDING = {"fingerprint": "f1", "tool": "semgrep", "category": "sast", "rule_id": "shell-true",
           "title": "subprocess with shell=True", "severity": "HIGH", "location": "app/main.py", "line": 2}


def test_tools_are_confined_to_repo(repo):
    assert "2: subprocess.run" in ai_triage.read_file(repo, "app/main.py", 1, 10)
    for bad in ("../etc/passwd", ".env", "/etc/passwd"):
        with pytest.raises(ai_triage.ToolError):
            ai_triage.read_file(repo, bad, 1, 5)
    assert "app/main.py:2" in ai_triage.search_code(repo, "shell=True")
    assert "TOKEN" not in ai_triage.search_code(repo, "TOKEN")


class FakeClient:
    """Plays back a tool call, then a final structured answer."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.requests = []
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.requests.append(kwargs)
        return self.replies.pop(0)


def test_agent_reads_code_then_returns_verdict(repo):
    tool_call = SimpleNamespace(stop_reason="tool_use", content=[
        SimpleNamespace(type="tool_use", id="t1", name="read_file",
                        input={"path": "app/main.py", "start_line": 1, "end_line": 5})])
    verdict = {"triage": [{"fingerprint": "f1", "verdict": "true_positive", "priority": "P1",
                           "rationale": "cmd comes from input", "fix": "pass a list, shell=False"},
                          {"fingerprint": "not-asked", "verdict": "false_positive", "priority": "P4",
                           "rationale": "-", "fix": "-"}]}
    final = SimpleNamespace(stop_reason="end_turn", content=[SimpleNamespace(type="text", text=json.dumps(verdict))])
    client = FakeClient([tool_call, final])

    results = ai_triage.triage_batch(client, "claude-opus-5-5", repo, [FINDING])

    assert results == [verdict["triage"][0]]  # verdicts for unknown fingerprints are dropped
    second = client.requests[1]["messages"]
    tool_result = second[-1]["content"][0]
    assert tool_result["tool_use_id"] == "t1" and "shell=True" in tool_result["content"]
    assert client.requests[0]["output_config"]["format"]["type"] == "json_schema"


def test_refusal_and_missing_verdicts_fall_back(repo):
    refusal = SimpleNamespace(stop_reason="refusal", content=[])
    results = ai_triage.triage_batch(FakeClient([refusal]), "m", repo, [FINDING])
    assert results[0]["verdict"] == "needs_human" and results[0]["priority"] == "P2"


def test_rule_based_priorities():
    assert ai_triage.rule_based({**FINDING, "category": "secret"})["priority"] == "P1"
    assert ai_triage.rule_based({**FINDING, "severity": "MEDIUM"})["priority"] == "P3"
