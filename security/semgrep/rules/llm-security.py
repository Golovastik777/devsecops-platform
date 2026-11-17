# Semgrep rule tests: `semgrep --test security/semgrep/rules/`
import os
import subprocess

import anthropic
import fastapi
import httpx

client = anthropic.Anthropic()


def run_generated_code():
    response = client.messages.create(model="m", max_tokens=10, system="s", messages=[])
    code = response.content[0].text
    # ruleid: llm-output-to-dangerous-sink
    eval(code)
    # ruleid: llm-output-to-dangerous-sink
    os.system(code)
    # ruleid: llm-output-to-dangerous-sink
    subprocess.run(code, shell=True)
    # ok: llm-output-to-dangerous-sink
    print(code)


def no_system_prompt():
    # ruleid: llm-call-without-system-prompt
    client.messages.create(model="m", max_tokens=10, messages=[])
    # ok: llm-call-without-system-prompt
    client.beta.messages.create(model="m", max_tokens=10, system="role and rules", messages=[])


# ruleid: fastapi-interactive-docs-enabled
public_app = fastapi.FastAPI(title="demo")
# ok: fastapi-interactive-docs-enabled
private_app = fastapi.FastAPI(title="demo", docs_url=None, redoc_url=None, openapi_url=None)

# ruleid: http-client-tls-verification-disabled
httpx.get("https://example.com", verify=False)
# ok: http-client-tls-verification-disabled
httpx.get("https://example.com")
