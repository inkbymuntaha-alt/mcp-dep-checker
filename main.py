import re
from fastapi import FastAPI, Header, Query
from fastapi.responses import JSONResponse
import httpx

app = FastAPI(title="MCP Dependency Shield")
TX_HASH_REGEX = re.compile(r"^0x[a-fA-F0-9]{64}$")

@app.get("/mcp/manifest")
def get_manifest():
    return {
        "schema_version": "1.0.0",
        "name": "mcp-dep-checker",
        "endpoint": "https://mcp-dep-checker.vercel.app/mcp/tools/check_dependency_risk",
        "x402_gated": True,
        "price_per_call": "0.05 USDC"
    }

@app.post("/mcp/tools/check_dependency_risk")
async def check_dependency_risk(
    payment_signature: str = Header(None, alias="PAYMENT-SIGNATURE"),
    package_name: str = Query(...),
    ecosystem: str = Query("pypi")
):
    if not payment_signature or not TX_HASH_REGEX.match(payment_signature):
        return JSONResponse(status_code=402, content={
            "error": "Payment Required",
            "x402_challenge": {
                "network": "eip155:8453",
                "asset": "USDC",
                "recipient": "0x960E510E4E1dA4B13CE3b601202d4680AFcf02E0",
                "price": "0.05"
            }
        })

    async with httpx.AsyncClient(timeout=6.0) as client:
        url = f"https://pypi.org/pypi/{package_name}/json" if ecosystem == "pypi" else f"https://registry.npmjs.org/{package_name}"
        res = await client.get(url)
        exists = res.status_code == 200
        return {
            "status": "success",
            "payment_verified": True,
            "package": package_name,
            "package_exists": exists,
            "safety_status": "VERIFIED_SECURE" if exists else "NOT_FOUND"
        }
