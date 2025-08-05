from motor.motor_asyncio import AsyncIOMotorClient
from urllib.parse import urlparse
from ..core.config import settings


class MongoDB:
    client: AsyncIOMotorClient = None
    db = None

    @staticmethod
    async def connect_to_mongo():
        # Setup MongoDB client
        MongoDB.client = AsyncIOMotorClient(settings.MONGODB_URI)

        # Extract DB name from URI or use default
        parsed = urlparse(settings.MONGODB_URI)
        db_name = settings.DATABASE_NAME or (parsed.path[1:] if parsed.path else "sakhi")

        # Connect to DB
        MongoDB.db = MongoDB.client[db_name]
        print(f"✅ Connected to MongoDB: {db_name}")

    @staticmethod
    async def close_mongo_connection():
        if MongoDB.client:
            MongoDB.client.close()
            print("❌ MongoDB connection closed")


# Global DB object
db = MongoDB()
