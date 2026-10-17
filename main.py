from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from cachetools import TTLCache
import detector

# 1. Initialize Rate Limiter (5 requests per minute per IP)
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="Phishing URL Detector API")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# 2. Initialize In-Memory Cache (Stores 1000 URLs, expires after 24 hours / 86400 seconds)
cache = TTLCache(maxsize=1000, ttl=86400)

# Configure CORS (Restricted to Netlify frontend)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://phishing-detectoor.netlify.app"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    url: str

@app.post("/api/scan")
@limiter.limit("5/minute")
async def scan_url(request: Request, payload: ScanRequest):
    target_url = payload.url
    
    # Check if we already scanned this URL in the last 24 hours
    if target_url in cache:
        result = cache[target_url]
        result["findings"].append("ℹ️ Result loaded from server cache.")
        return result
        
    try:
        # If not cached, run the heavy heuristic and API engine
        result = detector.analyze_url(target_url)
        cache[target_url] = result  # Save to cache for the next user
        return result
    except Exception as e:
        import traceback
        print("=== CRITICAL BACKEND CRASH ===")
        traceback.print_exc()
        print("==============================")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/")
async def root():
    return {"message": "Phishing Detector API is running."}