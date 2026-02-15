from google import genai
import os
from dotenv import load_dotenv

load_dotenv()

api_key = os.getenv('GEMINI_API_KEY')
if not api_key:
    print("Error: GEMINI_API_KEY not found.")
else:
    client = genai.Client(api_key=api_key)
    try:
        print("Listing available models with google-genai...")
        for m in client.models.list():
            print(m.name)
    except Exception as e:
        print(f"Error listing models: {e}")
