import base64
from typing import Dict, Any

def run_playwright_sandbox(initial_url: str) -> Dict[str, Any]:
    from playwright.sync_api import sync_playwright, TimeoutError
    
    result = {
        "screenshots": [],
        "final_url": initial_url,
        "is_mobile": False,
        "error": None
    }
    
    try:
        with sync_playwright() as p:
            # We use chromium in headless mode
            browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-setuid-sandbox"])
            
            # 1. First attempt with Desktop context
            context = browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                viewport={"width": 1280, "height": 800}
            )
            page = context.new_page()
            
            try:
                # We can intercept navigation to take screenshots of JS redirects
                page.goto(initial_url, timeout=15000, wait_until="domcontentloaded")
                # Wait briefly to let JS frameworks render
                page.wait_for_timeout(2000)
                
                content = page.content()
                
                # Check if suspiciously blank (possible mobile-only phishing or bot protection)
                is_blank = len(content) < 500 or "<body></body>" in content.replace(" ", "").lower()
                
                if is_blank:
                    result["is_mobile"] = True
                    context.close()
                    
                    # 2. Second attempt with Mobile context
                    context = browser.new_context(
                        user_agent="Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1",
                        viewport={"width": 375, "height": 812},
                        is_mobile=True,
                        has_touch=True
                    )
                    page = context.new_page()
                    page.goto(initial_url, timeout=15000, wait_until="domcontentloaded")
                    page.wait_for_timeout(2000)
                
                # Take final screenshot
                shot = page.screenshot(type="jpeg", quality=80, full_page=False)
                shot_b64 = base64.b64encode(shot).decode('utf-8')
                result["screenshots"].append({
                    "url": page.url,
                    "data": shot_b64,
                    "type": "final"
                })
                result["final_url"] = page.url
                
            except Exception as e:
                result["error"] = str(e)
            finally:
                browser.close()
    except Exception as e:
        result["error"] = f"Playwright error: {str(e)}"
        
    return result
