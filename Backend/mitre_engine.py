import os
import json
from typing import List, Optional, Dict
from pydantic import BaseModel
try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

# --- Data Models ---

class AttackNode(BaseModel):
    id: str
    label: str
    type: str # 'vulnerability' | 'technique' | 'goal' | 'start'
    mitre_id: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None  # For vulnerability nodes

class AttackEdge(BaseModel):
    source: str
    target: str
    description: Optional[str] = None

class AttackGraph(BaseModel):
    nodes: List[AttackNode]
    edges: List[AttackEdge]

# --- Static Mapper ---

VULN_TO_MITRE = {
    "SQL Injection": "T1190", # Exploit Public-Facing Application
    "Cross-Site Scripting": "T1059", # Command and Scripting Interpreter
    "Command Injection": "T1059",
    "Broken Authentication": "T1078", # Valid Accounts
    "Misconfiguration": "T1078",
    "Sensitive Data Exposure": "T1005", # Data from Local System
    "XML External Entity (XXE)": "T1190",
    "Insecure Deserialization": "T1203", # Exploitation for Client Execution
}

# --- Engine ---

class MitreEngine:
    def __init__(self):
        self.api_key = os.getenv("OPENAI_API_KEY")
        if OpenAI and self.api_key:
            self.client = OpenAI(api_key=self.api_key)
        else:
            self.client = None
            if not OpenAI:
                print("⚠️ OpenAI module not found. MitreEngine running in mock mode.")
            elif not self.api_key:
                print("⚠️ OPENAI_API_KEY not found. MitreEngine running in mock mode.")

    def simulate_attack_path(self, confirmed_vulns: List[Dict]) -> AttackGraph:
        nodes = []
        edges = []
        
        # 1. Start Node
        nodes.append(AttackNode(id="start", label="The Internet", type="start"))
        
        # 2. Vulnerability Nodes & Mapping
        technique_nodes = {} # Track unique techniques to avoid dupes
        
        for i, vuln in enumerate(confirmed_vulns):
            vuln_id = f"vuln_{i}"
            vuln_type = vuln.get("type", "Unknown Vulnerability")
            severity = vuln.get("severity", "MEDIUM")
            
            # Add Vuln Node with severity
            nodes.append(AttackNode(
                id=vuln_id,
                label=vuln_type,
                type="vulnerability",
                description=vuln.get("description"),
                severity=severity
            ))
            
            # Link Start -> Vuln
            edges.append(AttackEdge(source="start", target=vuln_id, description="External Access"))
            
            # Map to MITRE
            mitre_id = VULN_TO_MITRE.get(vuln_type)
            if not mitre_id:
                # Fuzzy match or default
                for key, val in VULN_TO_MITRE.items():
                    if key in vuln_type:
                        mitre_id = val
                        break
            
            if mitre_id:
                tech_id = f"tech_{mitre_id}"
                if tech_id not in technique_nodes:
                    technique_nodes[tech_id] = AttackNode(
                        id=tech_id,
                        label=f"MITRE {mitre_id}",
                        type="technique",
                        mitre_id=mitre_id
                    )
                    nodes.append(technique_nodes[tech_id])
                
                # Link Vuln -> Technique
                edges.append(AttackEdge(source=vuln_id, target=tech_id, description="Enables"))

        # 3. Simulation (AI or Mock)
        if not technique_nodes:
            return AttackGraph(nodes=nodes, edges=edges)

        if self.client:
            try:
                self._generate_ai_path(nodes, edges, list(technique_nodes.values()))
            except Exception as e:
                print(f"AI Simulation failed: {e}. Falling back to mock.")
                self._generate_mock_path(nodes, edges, list(technique_nodes.values()))
        else:
            self._generate_mock_path(nodes, edges, list(technique_nodes.values()))
            
        return AttackGraph(nodes=nodes, edges=edges)

    def _generate_mock_path(self, nodes, edges, techniques):
        # Create a generic Goal
        goal_node = AttackNode(id="goal_exfil", label="Data Exfiltration", type="goal", description="Theft of sensitive customer data.")
        nodes.append(goal_node)
        
        # Link all techniques to Goal
        for tech in techniques:
            edges.append(AttackEdge(source=tech.id, target=goal_node.id, description="Leads to"))

    def _generate_ai_path(self, nodes, edges, techniques):
        # Prepare prompt
        tech_list = ", ".join([f"{t.mitre_id}" for t in techniques])
        
        prompt = f"""
        Given these MITRE ATT&CK techniques as entry points: {tech_list}.
        Generate a realistic 3-step kill chain graph ending in a critical impact (e.g., Data Theft, Ransomware).
        Return ONLY a JSON object with 'nodes' and 'edges'.
        Nodes format: {{ "id": "...", "label": "...", "type": "technique"|"goal" }}
        Edges format: {{ "source": "...", "target": "..." }}
        Do not include the entry points in the output, only the subsequent steps.
        Connect the entry points to the first step of your generated chain.
        """
        
        response = self.client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert. Output JSON only."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3
        )
        
        try:
            content = response.choices[0].message.content
            # Clean markdown code blocks if present
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]
                
            data = json.loads(content.strip())
            
            # Parse AI nodes/edges
            generated_nodes = {}
            for n in data.get("nodes", []):
                node = AttackNode(id=n["id"], label=n["label"], type=n.get("type", "technique"))
                nodes.append(node)
                generated_nodes[n["id"]] = node
                
            for e in data.get("edges", []):
                edges.append(AttackEdge(source=e["source"], target=e["target"]))
                
            # Link entry techniques to the first generated node(s) if not explicitly linked
            # (The prompt asked to connect, but we need to handle the connection logic if the AI returns isolated subgraph)
            # For simplicity, let's assume the AI returns edges from the entry points if it knows their IDs. 
            # But we didn't give it the exact IDs we used (tech_TXXXX).
            # So we might need to link our techniques to the first node of the AI chain.
            
            if generated_nodes:
                first_ai_node = list(generated_nodes.values())[0]
                for tech in techniques:
                    edges.append(AttackEdge(source=tech.id, target=first_ai_node.id, description="Escalates to"))
                    
        except Exception as e:
            print(f"Error parsing AI response: {e}")
            self._generate_mock_path(nodes, edges, techniques)
