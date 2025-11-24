import pytest
from Backend.mitre_engine import MitreEngine, AttackNode, AttackGraph

def test_mitre_engine_initialization_no_openai(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "")
    engine = MitreEngine()
    assert engine.client is None

def test_mitre_engine_mock_path():
    engine = MitreEngine()
    engine.client = None # Force mock mode

    confirmed_vulns = [
        {"type": "SQL Injection", "severity": "HIGH", "description": "SQLi in login"},
        {"type": "Cross-Site Scripting", "severity": "MEDIUM", "description": "XSS in header"}
    ]

    graph = engine.simulate_attack_path(confirmed_vulns)

    assert isinstance(graph, AttackGraph)

    # Check nodes
    # Expect: Start + 2 Vulns + 2 Techniques (T1190, T1059) + 1 Goal = 6 nodes
    assert len(graph.nodes) >= 6

    start_node = next((n for n in graph.nodes if n.type == "start"), None)
    assert start_node is not None

    vuln_nodes = [n for n in graph.nodes if n.type == "vulnerability"]
    assert len(vuln_nodes) == 2

    tech_nodes = [n for n in graph.nodes if n.type == "technique"]
    assert len(tech_nodes) == 2

    goal_node = next((n for n in graph.nodes if n.type == "goal"), None)
    assert goal_node is not None
    assert goal_node.id == "goal_exfil"

def test_mitre_engine_unknown_vuln():
    engine = MitreEngine()
    engine.client = None

    confirmed_vulns = [
        {"type": "Unknown 0-day", "severity": "CRITICAL", "description": "???"}
    ]

    graph = engine.simulate_attack_path(confirmed_vulns)

    # Start + Vuln + (No Technique known) -> 2 nodes
    # Actually code logic might not add technique if not found in VULN_TO_MITRE

    vuln_node = next((n for n in graph.nodes if n.label == "Unknown 0-day"), None)
    assert vuln_node is not None

    # Check if any technique is linked
    tech_nodes = [n for n in graph.nodes if n.type == "technique"]
    assert len(tech_nodes) == 0

def test_mitre_engine_partial_match():
    engine = MitreEngine()
    engine.client = None

    confirmed_vulns = [
        {"type": "Stored Cross-Site Scripting", "severity": "MEDIUM", "description": "XSS"}
    ]

    graph = engine.simulate_attack_path(confirmed_vulns)

    tech_nodes = [n for n in graph.nodes if n.type == "technique"]
    assert len(tech_nodes) == 1
    # T1059 is for Cross-Site Scripting
    assert "T1059" in tech_nodes[0].label
