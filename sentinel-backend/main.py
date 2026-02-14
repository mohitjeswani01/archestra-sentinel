from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.v1 import discovery, governance, observability, security
from core.scanner import start_background_scanning

app = FastAPI(title="Archestra Sentinel Brain")

# CORS Configuration
# Force allow_origins=["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(discovery.router, prefix="/api/v1")
app.include_router(governance.router, prefix="/api/v1")
app.include_router(observability.router, prefix="/api/v1")
app.include_router(security.router, prefix="/api/v1")

@app.on_event("startup")
async def startup_event():
    # Start the background scanner thread
    print("Starting Background Docker Scanner...")
    start_background_scanning()

@app.get("/")
async def root():
    return {"message": "Archestra Sentinel Brain is Active"}
