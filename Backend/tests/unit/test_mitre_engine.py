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


class TestGetAttackPathGraph:
    """Tests for the new get_attack_path_graph function."""
    
    @pytest.fixture
    def engine_mock_mode(self):
        with patch('mitre_engine.OpenAI', None):
            return MitreEngine()

    @pytest.mark.asyncio
    async def test_nist_unavailable_falls_back_to_ai(self, engine_mock_mode):
        """Test that AI fallback is used when NIST data is unavailable."""
        with patch.object(engine_mock_mode, '_fetch_nist_cve', return_value=None):
            with patch.object(engine_mock_mode, '_generate_fallback_graph') as mock_fallback:
                mock_fallback.return_value = (
                    [
                        MagicMock(id="vuln_entry", label="Test Vuln"),
                        MagicMock(id="goal", label="Impact")
                    ],
                    [
                        MagicMock(from_node="vuln_entry", to="goal", description="Test")
                    ]
                )
                
                result = await engine_mock_mode.get_attack_path_graph("CVE-9999-99999")
                
                assert result.source == "AI-Generated"
                assert result.data_source_status.nist_available == False

    @pytest.mark.asyncio
    async def test_extract_severity(self, engine_mock_mode):
        """Test severity extraction from CVE data."""
        cve_data = {
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {
                        "baseSeverity": "CRITICAL"
                    }
                }]
            }
        }
        
        severity = engine_mock_mode._extract_severity(cve_data)
        assert severity == "Critical"

    @pytest.mark.asyncio
    async def test_extract_cwes(self, engine_mock_mode):
        """Test CWE extraction from CVE data."""
        cve_data = {
            "weaknesses": [{
                "description": [
                    {"value": "CWE-89"},
                    {"value": "CWE-79"}
                ]
            }]
        }
        
        cwes = engine_mock_mode._extract_cwes(cve_data)
        assert "CWE-89" in cwes
        assert "CWE-79" in cwes

    @pytest.mark.asyncio
    async def test_cwe_to_mitre_mapping(self, engine_mock_mode):
        """Test CWE to MITRE ATT&CK mapping."""
        cwe_ids = ["CWE-89", "CWE-79"]
        
        techniques = await engine_mock_mode._map_cwe_to_mitre(cwe_ids)
        
        # CWE-89 should map to T1190 (Exploit Public-Facing Application)
        assert any(t["id"] == "T1190" for t in techniques)
        # CWE-79 should map to T1059.007 (JavaScript Execution)
        assert any(t["id"] == "T1059.007" for t in techniques)

    def test_build_attack_graph(self, engine_mock_mode):
        """Test attack graph building from NIST/MITRE data."""
        techniques = [
            {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
            {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"}
        ]
        
        nodes, edges = engine_mock_mode._build_nist_attack_graph(
            "CVE-2021-44228",
            "Test vulnerability description",
            "Critical",
            techniques
        )
        
        # Should have: vuln_entry, 2 techniques, goal_impact
        assert len(nodes) == 4
        assert len(edges) == 3
        
        # First node should be vulnerability entry
        assert nodes[0].id == "vuln_entry"
        
        # Last node should be goal
        assert nodes[-1].id == "goal_impact"

    def test_validate_result(self, engine_mock_mode):
        """Test result validation."""
        from mitre_engine import AttackPathResult, AttackPathGraph, GraphNode, GraphEdge, DataSourceStatus
        
        valid_result = AttackPathResult(
            vulnerability_id="CVE-2021-44228",
            source="NIST",
            attack_path_graph=AttackPathGraph(
                nodes=[GraphNode(id="test", label="Test")],
                edges=[]
            ),
            data_source_status=DataSourceStatus(nist_available=True, mitre_available=True),
            severity="Critical",
            ordered_by_severity=True
        )
        
        # Should not raise
        engine_mock_mode._validate_result(valid_result)

    def test_generate_fallback_graph(self, engine_mock_mode):
        """Test fallback graph generation."""
        nodes, edges = engine_mock_mode._generate_fallback_graph("CVE-2021-44228")
        
        assert len(nodes) == 3
        assert len(edges) == 2
        assert nodes[0].id == "vuln_entry"
        assert "CVE-2021-44228" in nodes[0].label
