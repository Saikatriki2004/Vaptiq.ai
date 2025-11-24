import pytest
from unittest.mock import MagicMock, patch
from mitre_engine import MitreEngine, AttackNode, AttackEdge, AttackGraph

class TestMitreEngine:
    
    @pytest.fixture
    def mock_openai(self):
        with patch('mitre_engine.OpenAI') as mock:
            yield mock

    @pytest.fixture
    def engine_mock_mode(self):
        with patch('mitre_engine.OpenAI', None):
            return MitreEngine()

    @pytest.fixture
    def engine_ai_mode(self, mock_openai):
        with patch.dict('os.environ', {'OPENAI_API_KEY': 'test-key'}):
            return MitreEngine()

    def test_initialization_mock_mode(self):
        with patch('mitre_engine.OpenAI', None):
            engine = MitreEngine()
            assert engine.client is None

    def test_initialization_ai_mode(self, mock_openai):
        with patch.dict('os.environ', {'OPENAI_API_KEY': 'test-key'}):
            engine = MitreEngine()
            assert engine.client is not None

    def test_vuln_mapping(self, engine_mock_mode):
        vulns = [
            {"type": "SQL Injection", "severity": "HIGH", "description": "SQLi found"},
            {"type": "Unknown Vuln", "severity": "LOW"}
        ]
        
        graph = engine_mock_mode.simulate_attack_path(vulns)
        
        # Check nodes
        assert len(graph.nodes) >= 4  # Start, 2 Vulns, 1 Goal (mock), maybe techniques
        
        # Check SQLi mapping
        sqli_node = next((n for n in graph.nodes if n.label == "SQL Injection"), None)
        assert sqli_node is not None
        assert sqli_node.type == "vulnerability"
        
        # Check MITRE technique for SQLi (T1190)
        tech_node = next((n for n in graph.nodes if n.mitre_id == "T1190"), None)
        assert tech_node is not None
        assert tech_node.type == "technique"

    def test_fuzzy_mapping(self, engine_mock_mode):
        vulns = [{"type": "Possible SQL Injection Attack", "severity": "HIGH"}]
        graph = engine_mock_mode.simulate_attack_path(vulns)
        
        # Should still map to T1190 due to "SQL Injection" substring
        tech_node = next((n for n in graph.nodes if n.mitre_id == "T1190"), None)
        assert tech_node is not None

    def test_mock_path_generation(self, engine_mock_mode):
        vulns = [{"type": "SQL Injection", "severity": "HIGH"}]
        graph = engine_mock_mode.simulate_attack_path(vulns)
        
        # Should have a goal node in mock mode
        goal_node = next((n for n in graph.nodes if n.type == "goal"), None)
        assert goal_node is not None
        assert goal_node.id == "goal_exfil"
        
        # Should have edge to goal
        edge_to_goal = next((e for e in graph.edges if e.target == "goal_exfil"), None)
        assert edge_to_goal is not None

    def test_ai_path_generation_success(self, engine_ai_mode, mock_openai):
        # Mock OpenAI response
        mock_response = MagicMock()
        mock_response.choices[0].message.content = """
        ```json
        {
            "nodes": [
                {"id": "step1", "label": "Privilege Escalation", "type": "technique"},
                {"id": "step2", "label": "Ransomware", "type": "goal"}
            ],
            "edges": [
                {"source": "step1", "target": "step2"}
            ]
        }
        ```
        """
        engine_ai_mode.client.chat.completions.create.return_value = mock_response
        
        vulns = [{"type": "SQL Injection", "severity": "HIGH"}]
        graph = engine_ai_mode.simulate_attack_path(vulns)
        
        # Check if AI nodes are present
        assert any(n.id == "step1" for n in graph.nodes)
        assert any(n.id == "step2" for n in graph.nodes)
        
        # Check if entry technique is linked to AI chain
        # T1190 is the technique for SQLi
        tech_node = next(n for n in graph.nodes if n.mitre_id == "T1190")
        assert any(e.source == tech_node.id and e.target == "step1" for e in graph.edges)

    def test_ai_path_generation_failure_fallback(self, engine_ai_mode):
        # Mock OpenAI to raise exception
        engine_ai_mode.client.chat.completions.create.side_effect = Exception("API Error")
        
        vulns = [{"type": "SQL Injection", "severity": "HIGH"}]
        graph = engine_ai_mode.simulate_attack_path(vulns)
        
        # Should fall back to mock path (goal_exfil)
        assert any(n.id == "goal_exfil" for n in graph.nodes)

    def test_no_vulns(self, engine_mock_mode):
        graph = engine_mock_mode.simulate_attack_path([])
        
        assert len(graph.nodes) == 1  # Only start node
        assert graph.nodes[0].id == "start"
        assert len(graph.edges) == 0
