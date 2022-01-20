import pymongo
from pymongo import MongoClient
from decouple import config

def get_database():

    # Create a connection using MongoClient.

    client = MongoClient(config('CONNECTION_STRING'))

    # Create the database
    dbname = client[config('DATABASE_NAME')]
    collection_name = dbname[config('COLLECTION_NAME')]
    return collection_name
    
# This is added so that many files can reuse the function get_database()
if __name__ == "__main__":    
    
    # Get the database
    dbname = get_database()
    