from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.v1 import discovery

app = FastAPI(title="Archestra Sentinel Brain")

# CORS Configuration
origins = [
    "http://localhost:3000",
    "http://localhost:5173", # Vite default
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

@app.get("/")
async def root():
    return {"message": "Archestra Sentinel Brain is Active"}
