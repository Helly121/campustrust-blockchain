import os
import urllib.request

# Base URL for face-api.js models (original repo)
BASE_URL = "https://raw.githubusercontent.com/justadudewhohacks/face-api.js/master/weights/"

# Target directory
TARGET_DIR = r"d:\MLSC hackathon\campus-trust\campus-trust\static\models"

# List of files to download
FILES = [
    "tiny_face_detector_model-weights_manifest.json",
    "tiny_face_detector_model-shard1",
    "face_landmark_68_model-weights_manifest.json",
    "face_landmark_68_model-shard1",
    "face_recognition_model-weights_manifest.json",
    "face_recognition_model-shard1",
    "face_recognition_model-shard2"
]

def download_models():
    if not os.path.exists(TARGET_DIR):
        os.makedirs(TARGET_DIR)
        print(f"Created directory: {TARGET_DIR}")
    
    print(f"Downloading models to {TARGET_DIR}...")
    
    for file_name in FILES:
        url = BASE_URL + file_name
        dest_path = os.path.join(TARGET_DIR, file_name)
        
        print(f"Downloading {file_name}...")
        try:
            urllib.request.urlretrieve(url, dest_path)
            print(f" -> Success")
        except Exception as e:
            print(f" -> Failed: {e}")

    print("Download complete!")

if __name__ == "__main__":
    download_models()
