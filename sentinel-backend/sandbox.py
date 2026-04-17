import asyncio
import base64
import re
from playwright.async_api import async_playwright, TimeoutError as PWTimeout

class GhostSandbox:
    async def analyze(self, url: str) -> dict:
        result = {
            "screenshot_b64": None,
            "cookies_harvested": [],
            "suspicious_scripts": [],
            "redirect_chain": [],
            "form_fields": [],
            "geolocation_requested": False,
            "device_info_requested": False,
            "score": 0,
            "max_score": 25,
            "verdict": "Clean"
        }

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,
                    args=["--no-sandbox", "--disable-setuid-sandbox",
                          "--disable-dev-shm-usage", "--disable-gpu"]
                )
                context = await browser.new_context(
                    user_agent="Mozilla/5.0 (Linux; Android 11; Redmi Note 9) AppleWebKit/537.36",
                    viewport={"width": 390, "height": 844},
                    geolocation={"latitude": 13.0827, "longitude": 80.2707},
                    permissions=[]
                )

                page = await context.new_page()
                redirects = []
                suspicious_js = []

                page.on("request", lambda req: redirects.append(req.url)
                        if req.is_navigation_request() else None)

                # Intercept suspicious JS patterns
                await page.add_init_script("""
                    window.__sentinel_flags = {
                        geo: false,
                        deviceInfo: false,
                        cookieAccess: false
                    };
                    const origGeo = navigator.geolocation.getCurrentPosition.bind(navigator.geolocation);
                    navigator.geolocation.getCurrentPosition = function(...args) {
                        window.__sentinel_flags.geo = true;
                        return origGeo(...args);
                    };
                """)

                try:
                    await page.goto(url, wait_until="networkidle", timeout=15000)
                except PWTimeout:
                    await page.goto(url, wait_until="domcontentloaded", timeout=10000)

                # Screenshot
                screenshot_bytes = await page.screenshot(full_page=False)
                result["screenshot_b64"] = base64.b64encode(screenshot_bytes).decode()

                # Cookies
                cookies = await context.cookies()
                result["cookies_harvested"] = [
                    {"name": c["name"], "domain": c["domain"], "httpOnly": c["httpOnly"]}
                    for c in cookies
                ]

                # Redirect chain
                result["redirect_chain"] = list(dict.fromkeys(redirects))[:10]

                # Form fields (credential harvesting check)
                forms = await page.evaluate("""
                    () => Array.from(document.querySelectorAll('input')).map(i => ({
                        type: i.type, name: i.name, placeholder: i.placeholder
                    }))
                """)
                result["form_fields"] = forms

                # Geo/device flags
                flags = await page.evaluate("() => window.__sentinel_flags")
                result["geolocation_requested"] = flags.get("geo", False)
                result["device_info_requested"] = flags.get("deviceInfo", False)

                # JS source analysis
                scripts = await page.evaluate("""
                    () => Array.from(document.querySelectorAll('script')).map(s => s.innerText).join(' ')
                """)
                patterns = [
                    (r'document\.cookie', 'Cookie stealing detected'),
                    (r'localStorage', 'LocalStorage access detected'),
                    (r'eval\(', 'Obfuscated code (eval) detected'),
                    (r'atob\(', 'Base64 obfuscation detected'),
                    (r'keydown|keypress', 'Keylogger pattern detected'),
                    (r'navigator\.sendBeacon', 'Silent data exfiltration detected'),
                    (r'fetch\(|XMLHttpRequest', 'External data sending detected'),
                ]
                for pattern, label in patterns:
                    if re.search(pattern, scripts, re.IGNORECASE):
                        suspicious_js.append(label)

                result["suspicious_scripts"] = suspicious_js

                # Calculate score
                score = 0
                if len(result["cookies_harvested"]) > 3: score += 5
                if len(result["redirect_chain"]) > 2: score += 5
                if result["geolocation_requested"]: score += 5
                if len(suspicious_js) > 0: score += min(len(suspicious_js) * 3, 10)
                password_fields = [f for f in forms if f.get("type") == "password"]
                if password_fields: score += 5

                result["score"] = min(score, 25)
                result["verdict"] = (
                    "CRITICAL — Active attack detected" if score >= 20 else
                    "HIGH — Multiple suspicious behaviors" if score >= 12 else
                    "MEDIUM — Some suspicious activity" if score >= 6 else
                    "CLEAN — No obvious threats"
                )

                await browser.close()

        except Exception as e:
            result["verdict"] = f"Sandbox error: {str(e)}"

        return result
