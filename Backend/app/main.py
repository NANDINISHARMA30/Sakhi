from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
# We'll import these once they're created
from .api import auth, admin
from .db.mongodb import db
from .core.config import settings

app = FastAPI(
    title="Sakhi API",
    description="API for Sakhi roommate matching platform",
    version="1.0.0"
)

# Setup CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database connection events - uncomment when MongoDB is set up
@app.on_event("startup")
async def startup_db_client():
    await db.connect_to_mongo()

@app.on_event("shutdown")
async def shutdown_db_client():
    await db.close_mongo_connection()

# Include routers - uncomment when API routes are set up
app.include_router(auth.router, prefix=f"{settings.API_V1_STR}/auth", tags=["Authentication"])
app.include_router(admin.router, prefix=f"{settings.API_V1_STR}/admin", tags=["Admin"])

@app.get("/")
async def root():
    return {"message": "Welcome to Sakhi API"}