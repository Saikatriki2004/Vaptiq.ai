import asyncio
import os
import time
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

# --- Data Models ---

class SuspectedVuln(BaseModel):
    target_url: str
    vuln_type: str  # e.g., "SQL Injection", "XSS", "Command Injection"
    parameter: str  # e.g., "id", "q", "search"
    evidence_hint: str  # e.g., "Server returned 500 error on single quote"

class VerificationResult(BaseModel):
    is_confirmed: bool
    proof_of_exploit: str  # The exact payload that worked
    logs: str
    execution_time: float  # Time taken to verify

# --- The Verifier Brain (Hybrid OpenRouter + Privacy Mode) ---

class VerifierAgent:
    """
    🧠 Hybrid AI-Powered Vulnerability Verification Agent
    
    Architecture:
    - PRIVACY_MODE=HIGH → Direct Gemini (no third-party routing)
    - PRIVACY_MODE=LOW → OpenRouter (multi-model support)
    - Fallback → Mock mode (no API needed)
    
    Features:
    - Intelligent retry logic (3 attempts)
    - Cost tracking and logging
    - Graceful degradation to mock mode
    - Security-focused with 5-second sandbox timeout
    """
    
    def __init__(self):
        # Read configuration
        self.llm_provider = os.getenv("LLM_PROVIDER", "OPENROUTER").upper()
        self.privacy_mode = os.getenv("PRIVACY_MODE", "LOW").upper()
        
        # Privacy Mode Override: Force direct APIs if HIGH
        if self.privacy_mode == "HIGH":
            print("🔒 PRIVACY MODE ACTIVE: Bypassing third-party aggregators.")
            self.llm_provider = "GEMINI"  # Force direct Gemini
        
        # Initialize client based on provider
        self.mode = "MOCK"  # Default to mock
        self.client = None
        self.model = None
        
        try:
            from openai import AsyncOpenAI
            
            if self.llm_provider == "OPENROUTER":
                api_key = os.getenv("OPENROUTER_API_KEY")
                if api_key:
                    self.client = AsyncOpenAI(
                        base_url="https://openrouter.ai/api/v1",
                        api_key=api_key,
                    )
                    self.model = os.getenv("OPENROUTER_MODEL", "moonshotai/kimi-k2-thinking")
                    self.mode = "REAL"
                    print(f"🌐 OPENROUTER ACTIVE: Using model {self.model}")
                    print(f"   Privacy Mode: {self.privacy_mode}")
                else:
                    print("⚠️ OPENROUTER_API_KEY not found. Falling back to MOCK mode.")
                    
            elif self.llm_provider == "GEMINI":
                api_key = os.getenv("GEMINI_API_KEY")
                if api_key:
                    self.client = AsyncOpenAI(
                        base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
                        api_key=api_key,
                    )
                    self.model = "gemini-2.0-flash-exp"
                    self.mode = "REAL"
                    print(f"🔐 GEMINI DIRECT: Using model {self.model}")
                    print(f"   Privacy Mode: {self.privacy_mode} (Direct - No third-party routing)")
                else:
                    print("⚠️ GEMINI_API_KEY not found. Falling back to MOCK mode.")
                    
            elif self.llm_provider == "KIMI":
                api_key = os.getenv("MOONSHOT_API_KEY")
                if api_key:
                    self.client = AsyncOpenAI(
                        base_url="https://api.moonshot.ai/v1",
                        api_key=api_key
                    )
                    self.model = "kimi-k2-thinking"
                    self.mode = "REAL"
                    print(f"🌙 KIMI DIRECT: Using model {self.model}")
                else:
                    print("⚠️ MOONSHOT_API_KEY not found. Falling back to MOCK mode.")
                    
        except ImportError:
            print("⚠️ openai library not installed. Install with: pip install openai")
            print("   Falling back to MOCK mode.")
        except Exception as e:
            print(f"⚠️ Error initializing LLM client: {e}")
            print("   Falling back to MOCK mode.")
        
        if self.mode == "MOCK":
            print("🎭 MOCK MODE ACTIVE: Using deterministic verification scripts (no API costs)")

    def _construct_prompt(self, suspicion: SuspectedVuln) -> str:
        """
        Constructs the prompt that asks the LLM to write a Python validation script.
        """
        return f"""You are a Senior Penetration Tester.
Task: Write a Python function named `verify()` to validate a suspected {suspicion.vuln_type}.

Target: {suspicion.target_url}
Parameter: {suspicion.parameter}
Context: {suspicion.evidence_hint}

Requirements:
1. Use ONLY the `requests` library (already imported).
2. The function MUST return a Boolean: True if vulnerable, False if not.
3. Handle ALL exceptions gracefully (return False on timeout/errors).
4. Do NOT perform destructive actions (DROP TABLE, DELETE, etc.).
5. Use a timeout of 3 seconds for all requests.
6. Return ONLY the Python code for the verify() function, no markdown, no explanation, no imports.

Example Logic for SQL Injection:
- Send payload with ' AND 1=1-- and ' AND 1=2--
- Compare response lengths or status codes
- If significant difference or error, return True

Generate the verify() function code now:"""

    async def _generate_script_mock(self, suspicion: SuspectedVuln) -> str:
        """
        Mock LLM response for testing without API costs.
        Returns deterministic scripts based on vulnerability type.
        """
        print(f"🎭 MOCK MODE: Generating deterministic script for {suspicion.vuln_type}")
        
        if "SQL" in suspicion.vuln_type.upper():
            return f"""
def verify():
    import requests
    target = "{suspicion.target_url}"
    param = "{suspicion.parameter}"
    
    try:
        # Control payload
        resp_normal = requests.get(target, params={{param: "1"}}, timeout=3)
        
        # SQL injection test payloads
        resp_sqli_1 = requests.get(target, params={{param: "1' OR '1'='1"}}, timeout=3)
        resp_sqli_2 = requests.get(target, params={{param: "1' AND '1'='2"}}, timeout=3)
        
        # Heuristic: Check for errors or length changes
        if resp_normal.status_code == 200:
            if resp_sqli_1.status_code == 500 or resp_sqli_2.status_code == 500:
                return True
            if abs(len(resp_sqli_1.text) - len(resp_normal.text)) > 100:
                return True
        
        return False
    except Exception as e:
        return False
"""
        elif "XSS" in suspicion.vuln_type.upper():
            return f"""
def verify():
    import requests
    target = "{suspicion.target_url}"
    param = "{suspicion.parameter}"
    
    try:
        # XSS probe payload
        xss_payload = "<script>alert('XSS')</script>"
        resp = requests.get(target, params={{param: xss_payload}}, timeout=3)
        
        # Check if payload is reflected unescaped
        if xss_payload in resp.text or "<script>" in resp.text:
            return True
        
        return False
    except Exception:
        return False
"""
        else:
            # Generic verification for other types
            return f"""
def verify():
    import requests
    target = "{suspicion.target_url}"
    param = "{suspicion.parameter}"
    
    try:
        # Basic anomaly detection
        resp_normal = requests.get(target, params={{param: "test"}}, timeout=3)
        resp_malicious = requests.get(target, params={{param: "test'<>\\"|"}}, timeout=3)
        
        # Check for error states
        if resp_normal.status_code == 200 and resp_malicious.status_code >= 500:
            return True
        
        return False
    except Exception:
        return False
"""

    async def _generate_script_real(self, suspicion: SuspectedVuln) -> str:
        """
        Real LLM-powered script generation with retry logic and fallback.
        """
        print(f"🧠 {self.llm_provider} MODE: Generating verification script for {suspicion.vuln_type}")
        
        prompt = self._construct_prompt(suspicion)
        
        # Retry logic: 3 attempts with 1-second delay
        max_retries = 3
        for attempt in range(1, max_retries + 1):
            try:
                # Prepare request parameters
                request_params = {
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": "You are an expert penetration testing script generator. Return only valid Python code."},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.8,  # Higher for creative exploit generation
                    "max_tokens": 500
                }
                
                # Add OpenRouter-specific headers
                if self.llm_provider == "OPENROUTER":
                    request_params["extra_headers"] = {
                        "HTTP-Referer": "https://vaptiq.ai",
                        "X-Title": "Vaptiq.ai VAPT Platform"
                    }
                
                # Make API call
                response = await self.client.chat.completions.create(**request_params)
                
                # Cost tracking
                if hasattr(response, 'usage') and response.usage:
                    tokens_used = response.usage.total_tokens
                    print(f"💰 Tokens used: {tokens_used} (~${tokens_used * 0.00001:.6f} estimated)")
                
                # Extract generated code
                generated_code = response.choices[0].message.content.strip()
                
                # Clean up markdown if LLM still included it
                if "```python" in generated_code:
                    generated_code = generated_code.split("```python")[1].split("```")[0].strip()
                elif "```" in generated_code:
                    generated_code = generated_code.split("```")[1].split("```")[0].strip()
                
                print(f"✅ Script generated successfully (attempt {attempt})")
                return generated_code
                
            except Exception as e:
                error_msg = str(e)
                print(f"❌ API Error (attempt {attempt}/{max_retries}): {error_msg}")
                
                if attempt < max_retries:
                    print(f"⏳ Retrying in 1 second...")
                    await asyncio.sleep(1)
                else:
                    print(f"⚠️ All {max_retries} attempts failed. Falling back to mock mode for this request.")
                    return await self._generate_script_mock(suspicion)
        
        # Fallback (should never reach here, but just in case)
        return await self._generate_script_mock(suspicion)

    async def generate_script(self, suspicion: SuspectedVuln) -> str:
        """
        Generates verification script using either mock or real LLM.
        """
        if self.mode == "MOCK":
            return await self._generate_script_mock(suspicion)
        else:
            return await self._generate_script_real(suspicion)

    async def execute_in_sandbox(self, code: str) -> bool:
        """
        Executes the generated Python code in a restricted sandbox with timeout.
        
        ⚠️⚠️⚠️ CRITICAL SECURITY WARNING ⚠️⚠️⚠️
        
        This function uses exec() which enables ARBITRARY CODE EXECUTION.
        exec() is EXTREMELY DANGEROUS in production environments and can lead to:
        - Remote Code Execution (RCE)
        - Server compromise
        - Data exfiltration
        - Lateral movement attacks
        
        PRODUCTION DEPLOYMENT REQUIREMENTS:
        1. Set ENABLE_CODE_EXECUTION=false (default) to disable this feature
        2. Replace with sandboxed alternatives:
           - Docker containers with network isolation
           - E2B (https://e2b.dev) - serverless code execution
           - AWS Lambda with strict IAM policies
           - Firecracker microVMs
        
        SAFETY FEATURES (INSUFFICIENT FOR PRODUCTION):
        - 5-second timeout using asyncio.wait_for
        - Restricted local scope
        - Exception handling
        - Production gate via environment variable
        
        DO NOT ENABLE IN PRODUCTION WITHOUT PROPER SANDBOXING!
        """
        
        # Production safety gate
        enable_exec = os.getenv("ENABLE_CODE_EXECUTION", "false").lower() == "true"
        
        if not enable_exec:
            print("🚫 CODE EXECUTION DISABLED (ENABLE_CODE_EXECUTION=false)")
            print("⚠️  Set ENABLE_CODE_EXECUTION=true in .env to enable (NOT RECOMMENDED FOR PRODUCTION)")
            print("📖 For production, use Docker/E2B/Lambda sandboxing instead")
            return False
        
        print("⚠️⚠️⚠️ WARNING: Code execution is ENABLED")
        print("📦 SANDBOX: Executing verification script with 5s timeout...")
        
        # Create restricted execution context
        local_scope = {"requests": __import__("requests")}
        
        async def run_verification():
            try:
                # Import requests for the script
                local_scope["requests"] = __import__("requests")
                
                # ⚠️ DANGER ZONE: Arbitrary code execution
                exec(code, {"__builtins__": __builtins__, "requests": __import__("requests")}, local_scope)
                
                # Run the verify function if it exists
                if 'verify' in local_scope and callable(local_scope['verify']):
                    # Run in executor to avoid blocking
                    loop = asyncio.get_event_loop()
                    result = await loop.run_in_executor(None, local_scope['verify'])
                    return bool(result)
                else:
                    print("❌ Error: Generated code did not contain a verify() function.")
                    return False
                    
            except Exception as e:
                print(f"❌ Sandbox Execution Error: {e}")
                return False
        
        try:
            # Apply 5-second timeout
            result = await asyncio.wait_for(run_verification(), timeout=5.0)
            return result
            
        except asyncio.TimeoutError:
            print("⏱️ Execution timeout: Script took longer than 5 seconds")
            return False
        except Exception as e:
            print(f"❌ Sandbox Error: {e}")
            return False

    async def verify_vulnerability(self, suspicion: SuspectedVuln) -> VerificationResult:
        """
        Main verification workflow:
        1. Generate custom exploit script
        2. Execute in sandbox with timeout
        3. Return verification result
        """
        start_time = datetime.now()
        
        print(f"\n{'='*60}")
        print(f"🔍 VERIFYING: {suspicion.vuln_type} on {suspicion.target_url}")
        print(f"📍 Parameter: {suspicion.parameter}")
        print(f"💡 Evidence: {suspicion.evidence_hint}")
        print(f"{'='*60}\n")
        
        # Step 1: Generate the verification script
        script = await self.generate_script(suspicion)
        print(f"📝 Generated Script:\n{script}\n")
        
        # Step 2: Execute the script in sandbox
        is_confirmed = await self.execute_in_sandbox(script)
        
        # Calculate execution time
        execution_time = (datetime.now() - start_time).total_seconds()
        
        # Step 3: Return structured result
        if is_confirmed:
            result = VerificationResult(
                is_confirmed=True,
                proof_of_exploit=f"Vulnerability confirmed via automated verification on parameter '{suspicion.parameter}'. "
                                f"Custom payload analysis detected anomalous behavior consistent with {suspicion.vuln_type}.",
                logs=f"[{self.mode} MODE - {self.llm_provider}] Agent generated verification script. Execution time: {execution_time:.2f}s. "
                     f"Result: VULNERABLE ✓",
                execution_time=execution_time
            )
            print(f"\n🔴 VERDICT: CONFIRMED VULNERABILITY")
        else:
            result = VerificationResult(
                is_confirmed=False,
                proof_of_exploit="",
                logs=f"[{self.mode} MODE - {self.llm_provider}] Verification script executed but did not confirm vulnerability. "
                     f"Execution time: {execution_time:.2f}s. Result: Likely false positive.",
                execution_time=execution_time
            )
            print(f"\n🟢 VERDICT: NOT CONFIRMED (False Positive)")
        
        print(f"{'='*60}\n")
        return result


# --- Integration Test ---
if __name__ == "__main__":
    import asyncio
    
    # Test case 1: SQL Injection
    suspect_sqli = SuspectedVuln(
        target_url="http://testphp.vulnweb.com/artists.php",
        vuln_type="SQL Injection",
        parameter="artist",
        evidence_hint="MySQL error message appeared when injecting single quote"
    )
    
    # Test case 2: XSS
    suspect_xss = SuspectedVuln(
        target_url="http://testphp.vulnweb.com/search.php",
        vuln_type="Cross-Site Scripting (XSS)",
        parameter="searchFor",
        evidence_hint="Script tag was reflected in the response unescaped"
    )
    
    async def run_tests():
        agent = VerifierAgent()
        
        # Test SQL Injection verification
        print("\n" + "="*80)
        print("TEST 1: SQL Injection Verification")
        print("="*80)
        result1 = await agent.verify_vulnerability(suspect_sqli)
        print(f"\nResult: {'✅ CONFIRMED' if result1.is_confirmed else '❌ NOT CONFIRMED'}")
        print(f"Proof: {result1.proof_of_exploit}")
        print(f"Logs: {result1.logs}")
        
        # Test XSS verification
        print("\n" + "="*80)
        print("TEST 2: XSS Verification")
        print("="*80)
        result2 = await agent.verify_vulnerability(suspect_xss)
        print(f"\nResult: {'✅ CONFIRMED' if result2.is_confirmed else '❌ NOT CONFIRMED'}")
        print(f"Proof: {result2.proof_of_exploit}")
        print(f"Logs: {result2.logs}")
    
    asyncio.run(run_tests())
