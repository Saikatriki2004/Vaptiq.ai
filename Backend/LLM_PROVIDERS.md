# Multi-Provider LLM Configuration Guide

The Verifier Agent now supports three AI providers:

## Supported Providers

### 1. OpenAI (GPT-4)
```env
LLM_PROVIDER=OPENAI
OPENAI_API_KEY=sk-...
```
- **Model**: `gpt-4`
- **Best for**: Highest quality, most reliable
- **Cost**: ~$0.03 per 1K tokens

### 2. Kimi (Moonshot) - K2 Thinking Model
```env
LLM_PROVIDER=KIMI
MOONSHOT_API_KEY=sk-...
```
- **Model**: `kimi-k2-thinking`
- **Best for**: Cost-effective, good reasoning
- **Base URL**: `https://api.moonshot.ai/v1`
- **Cost**: Lower than OpenAI

### 3. Gemini (Google) - 3.0 Pro
```env
LLM_PROVIDER=GEMINI
GEMINI_API_KEY=AIzaSy...
```
- **Model**: `gemini-3.0-pro`
- **Best for**: Fast inference, multimodal
- **Base URL**: `https://generativelanguage.googleapis.com/v1beta/openai/`
- **Cost**: Competitive pricing

## Configuration

Edit `apps/engine/.env`:

```env
# Choose your provider (OPENAI, KIMI, or GEMINI)
LLM_PROVIDER=KIMI

# Add the corresponding API key
MOONSHOT_API_KEY=your-actual-key
```

## Testing

```bash
cd apps/engine
python verifier_agent.py
```

You should see:
```
🤖 VerifierAgent initialized in REAL mode using KIMI provider
   ✓ Using Kimi (Moonshot) model: kimi-k2-thinking
```

## Fallback Behavior

If no API key is found, the agent automatically falls back to **MOCK mode** (no API calls, deterministic testing).
