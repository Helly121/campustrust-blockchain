
import os
import time
from google import genai
from dotenv import load_dotenv

load_dotenv()

api_key = os.environ.get('GEMINI_API_KEY')
client = genai.Client(api_key=api_key)

models_to_try = [
    'gemini-2.0-flash-lite',
    'gemini-1.5-flash',
    'gemini-2.0-flash',
]


def test_chat(message):
    system_instruction = "You are a helpful assistant."
    response = None
    last_error = None
    max_retries = 3
    
    # Try flash-lite first as it's most likely to be available on free tier
    models_to_try = [
        'gemini-2.0-flash-lite',
        'gemini-2.0-flash',
    ]
    
    for model_name in models_to_try:
        if model_name == 'gemini-1.5-flash': continue # Skip 404 model

        for attempt in range(max_retries):
            try:
                print(f"Testing {model_name} (Attempt {attempt+1})")
                response = client.models.generate_content(
                    model=model_name,
                    contents=f"{system_instruction}\n\nUSER QUESTION: {message}"
                )
                if response:
                    return f"SUCCESS with {model_name}: {response.text[:100]}..."
            except Exception as e:
                last_error = e
                error_str = str(e).upper()
                print(f"Error detail: {e}")
                if "429" in error_str or "RESOURCE_EXHAUSTED" in error_str:
                    wait_time = (attempt + 1) * 10 # 10s, 20s, 30s
                    print(f"Rate limited. Waiting {wait_time}s...")
                    time.sleep(wait_time)
                else:
                    print(f"Non-retryable error with {model_name}")
                    break
    
    return f"FINAL RESULT: FAILED. Last Error: {last_error}"

if __name__ == "__main__":
    print(test_chat("Tell me a short joke."))
