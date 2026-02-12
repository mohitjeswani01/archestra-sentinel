from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.v1 import discovery, governance, observability, security

app = FastAPI(title="Archestra Sentinel Brain")

# CORS Configuration
origins = [
    "http://localhost:3000",
    "http://localhost:8080", # Vite default
    "http://127.0.0.1:8080",
    "*" # Allow all for hackathon convenience
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(discovery.router, prefix="/api/v1")
app.include_router(governance.router, prefix="/api/v1")
app.include_router(observability.router, prefix="/api/v1")
app.include_router(security.router, prefix="/api/v1")

@app.get("/")
async def root():
    return {"message": "Archestra Sentinel Brain is Active"}
