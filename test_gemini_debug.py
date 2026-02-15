
import os
from dotenv import load_dotenv
from google import genai

load_dotenv()

api_key = os.environ.get('GEMINI_API_KEY')
print(f"Testing Key: {api_key[:10]}...") 

print("-" * 20)
try:
    client = genai.Client(api_key=api_key)
    
    model_name = 'gemini-1.5-flash'
    print(f"\nTesting {model_name}...")
    try:
        response = client.models.generate_content(
            model=model_name,
            contents='Hello, how are you?'
        )
        print(f"SUCCESS with {model_name}!")
        print(f"Response: {response.text}")
    except Exception as e:
        print(f"FAILED {model_name}: {e}")
        if hasattr(e, 'status_code'):
             print(f"Status Code: {e.status_code}")
        import traceback
        traceback.print_exc()

except Exception as e:
    print(f"Global Error: {e}")
