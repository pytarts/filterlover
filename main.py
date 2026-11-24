import asyncio
import base64
import json
import re
from pathlib import Path
from urllib.parse import quote

import httpx
import websockets
from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel

BASE_DIR = Path(__file__).resolve().parent
JSON_DIR = BASE_DIR / "json"
PUBLIC_DIR = BASE_DIR / "public"

# Build filter hosts from parts so copy-paste never strips subdomains
LS_HOST = ".".join(["production-gc", "lsfilter", "com"])
LS_QUERY = (
    "a=0ef9b862-b74f-4e8d-8aad-be549c5f452a"
    "&customer_id=74-1082-F000"
    "&agentType=chrome_extension"
    "&agentVersion=3.777.0"
    "&userGuid=00000000-0000-0000-0000-000000000000"
)
LS_WS_URL = f"wss://{LS_HOST}?{LS_QUERY}"

LW_HOST = ".".join(["mvgateway", "syd-1", "linewize", "net"])
SENSO_HOST = ".".join(["filtering", "senso", "cloud"])
LANSCHOOL_HOST = ".".join(["filter", "wavenetcloud", "netsweeper", "com"]) + ":3431"
BLOCKSI_STD_HOST = ".".join(["service1", "blocksi", "net"])
BLOCKSI_AI_HOST = ".".join(["api", "blocksi", "net"])

LINEWIZE_BLOCKED = {
    "animeandmanga", "dynamicdns", "trackers", "celebrities", "entertainment",
    "humouranddistractions", "livestreaming", "media", "socialmediaandcommunication",
    "marijuana", "crypto", "gamestorespublishers", "videogames", "blocklist.proxies",
    "aitools", "blocklist.dating", "blocklist.piracy", "whatsmyipservices", "p2p",
    "unsafesearchengines", "porn", "extreme", "malware", "matureandexplicit",
    "gamingresources", "offensive",
}

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    )
}


def load_json(filename: str, fallback):
    filepath = JSON_DIR / filename
    if filepath.exists():
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    return fallback


BLOCKSI_DATA = load_json("blocksi.json", {"web": {}, "ai": {}})
LANSCHOOL_DATA = load_json("lanschool.json", {})
LIGHTSPEED_LIST = load_json("lightspeed.json", [])
SENSO_DATA = load_json("senso.json", {})

LIGHTSPEED_MAP = {
    str(item.get("CategoryNumber")): {
        "name": item.get("CategoryName", "Unknown"),
        "allow": str(item.get("Allow")) == "1",
    }
    for item in LIGHTSPEED_LIST
}


async def check_lightspeed(domain: str) -> dict:
    try:
        async with asyncio.timeout(6):
            async with websockets.connect(LS_WS_URL) as ws:
                await ws.send(json.dumps({
                    "action": "dy_lookup",
                    "host": domain,
                    "ip": "174.85.104.135",
                    "customerId": "74-1082-F000",
                }))
                payload = json.loads(await ws.recv())
                cat_id = str(payload.get("cat", ""))
                info = LIGHTSPEED_MAP.get(cat_id)
                if info:
                    return {"category": info["name"], "blocked": not info["allow"]}
                return {"category": "Uncategorized", "blocked": True}
    except Exception:
        return {"category": "Error", "blocked": None}


async def check_linewize(client: httpx.AsyncClient, domain: str) -> dict:
    url = (
        f"https://{LW_HOST}/get/verdict"
        "?deviceid=PHYS-SMIC-US-0000-3190&cev=3.3.0&identity=null"
        f"&requested_website={quote(domain)}"
    )
    try:
        res = await client.get(url)
        data = res.json()
        sigs = data.get("signatures") or {}
        sub_cat = (
            (sigs.get("subCategory") or "")
            .replace("sphirewall.application.", "")
            .replace("sphirewall.category.", "")
        )
        cat = (
            (sigs.get("category") or "")
            .replace("sphirewall.application.", "")
            .replace("sphirewall.category.", "")
        )
        if not sub_cat:
            return {"category": "Not Rated", "blocked": False}
        blocked = (
            cat in LINEWIZE_BLOCKED
            or sub_cat in LINEWIZE_BLOCKED
            or sub_cat.startswith("blocklist.")
        )
        return {"category": sub_cat, "blocked": blocked}
    except Exception:
        return {"category": "Error", "blocked": None}


async def check_senso(client: httpx.AsyncClient, domain: str) -> dict:
    try:
        res = await client.get(f"https://{SENSO_HOST}/filter/lookup?url=https://{domain}")
        cat_ids = res.json()
        names = []
        blocked = False
        for cid in cat_ids:
            entry = SENSO_DATA.get(str(cid))
            if entry:
                names.append(entry[0])
                if entry[1]:
                    blocked = True
        if not names:
            return {"category": "Uncategorized", "blocked": True}
        return {"category": ", ".join(names), "blocked": blocked}
    except Exception:
        return {"category": "Error", "blocked": None}


async def check_lanschool(client: httpx.AsyncClient, domain: str) -> dict:
    try:
        raw_query = f"001 https://{domain} - - - - 3372822944"
        encoded = base64.b64encode(raw_query.encode("utf-8")).decode("utf-8")
        res = await client.get(f"https://{LANSCHOOL_HOST}/{encoded}")
        text = res.text
        if text.startswith("ALLOW"):
            return {"category": "Allowed", "blocked": False}
        match = re.search(r"[?&]cat=([^&\s]+)", text)
        if not match:
            return {"category": "Blocked", "blocked": True}
        names = [LANSCHOOL_DATA.get(cid, cid) for cid in match.group(1).split(",")]
        return {"category": ", ".join(names), "blocked": True}
    except Exception:
        return {"category": "Error", "blocked": None}


async def check_blocksi_std(client: httpx.AsyncClient, domain: str) -> dict:
    try:
        res = await client.get(f"https://{BLOCKSI_STD_HOST}/getRating.json?url={domain}")
        data = res.json()
        entry = BLOCKSI_DATA.get("web", {}).get(str(data.get("Category")))
        if not entry:
            return {"category": "Unknown", "blocked": True}
        return {
            "category": f"{entry['cat']}: {entry['name']}",
            "blocked": bool(entry["blocked"]),
        }
    except Exception:
        return {"category": "Error", "blocked": None}


async def check_blocksi_ai(client: httpx.AsyncClient, domain: str) -> dict:
    try:
        res = await client.post(
            f"https://{BLOCKSI_AI_HOST}/url-classifier-llm/predict_url",
            headers={
                "authorization": "Basic QXp6YXo6QmxvY2tzaUthcmlt",
                "content-type": "application/json",
            },
            json={"url": domain},
        )
        data = res.json()
        category = (
            data["document"]["predicted_specific_category"]
            if "document" in data
            else data.get("predicted_specific_category", "Unknown")
        )
        if category == "Specific Category":
            category = "Unknown"
        blocked = True
        for entry in BLOCKSI_DATA.get("ai", {}).values():
            if entry.get("name") == category and entry.get("blocked") is False:
                blocked = False
                break
        return {"category": category, "blocked": blocked}
    except Exception:
        return {"category": "Error", "blocked": None}


def extract_domains(text: str) -> list[str]:
    pattern = r"(?:https?://)?(?:www\.)?([a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)"
    matches = re.findall(pattern, text.lower())
    seen = set()
    unique = []
    for d in matches:
        if d not in seen:
            seen.add(d)
            unique.append(d)
    return unique[:15]


async def evaluate_domain(client: httpx.AsyncClient, domain: str) -> dict:
    ls, lw, sn, ln, bs, ba = await asyncio.gather(
        check_lightspeed(domain),
        check_linewize(client, domain),
        check_senso(client, domain),
        check_lanschool(client, domain),
        check_blocksi_std(client, domain),
        check_blocksi_ai(client, domain),
    )
    return {
        "domain": domain,
        "filters": {
            "lightspeed": ls,
            "linewize": lw,
            "senso": sn,
            "lanschool": ln,
            "blocksi": bs,
            "blocksi_ai": ba,
        },
    }


app = FastAPI(title="Link Checker")


class CheckRequest(BaseModel):
    text: str


@app.get("/")
def serve_frontend():
    return FileResponse(PUBLIC_DIR / "index.html")


@app.post("/api/check")
async def check_links(payload: CheckRequest):
    domains = extract_domains(payload.text)
    if not domains:
        return {"results": [], "error": "No valid URLs or domains found."}
    async with httpx.AsyncClient(
        timeout=6.0, verify=False, headers=DEFAULT_HEADERS
    ) as client:
        results = await asyncio.gather(*(evaluate_domain(client, d) for d in domains))
    return {"results": results}
