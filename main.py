import re
from concurrent.futures import ThreadPoolExecutor
import requests
from bs4 import BeautifulSoup
from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel

app = FastAPI()

class CheckRequest(BaseModel):
    text: str

def check_fortiguard(domain: str) -> str:
    url = f"https://fortiguard.com{domain}"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    try:
        res = requests.get(url, headers=headers, timeout=6)
        soup = BeautifulSoup(res.text, "html.parser")
        title_tag = soup.find("h4", class_="info_title")
        if title_tag and "Category:" in title_tag.text:
            return title_tag.text.replace("Category:", "").strip()
        return "Unrated / Captcha"
    except Exception:
        return "Lookup Error"

def check_lightspeed(domain: str) -> str:
    url = f"https://lightspeedsystems.com{domain}"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    try:
        res = requests.get(url, headers=headers, timeout=6)
        text = res.text
        if "Categorized as:" in text:
            part = text.split("Categorized as:")[1]
            category = part.split("<")[0].strip()
            return category if category else "Unknown"
        return "Unrated / Not Found"
    except Exception:
        return "Lookup Error"

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

def check_single_domain(domain: str) -> dict:
    return {
        "domain": domain,
        "fortiguard": check_fortiguard(domain),
        "lightspeed": check_lightspeed(domain),
    }

@app.get("/")
def read_root():
    return FileResponse("public/index.html")

@app.post("/api/check")
def check_links(payload: CheckRequest):
    domains = extract_domains(payload.text)
    if not domains:
        return {"results": [], "error": "No valid URLs or domains found."}
    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(check_single_domain, domains))
    return {"results": results}
