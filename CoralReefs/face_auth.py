import cv2
import os
import pickle
import numpy as np
import time

# Try to import face_recognition (dlib-based, more accurate)
try:
    import face_recognition
    has_fr = True
except ImportError:
    has_fr = False
    print("Warning: 'face_recognition' library not found. Falling back to OpenCV LBPH.")

class FaceAuthenticator:
    def __init__(self, data_dir=""):
        self.data_dir = data_dir
        self.encodings_file = os.path.join(data_dir, "owner_encodings.pkl")
        self.model_file = os.path.join(data_dir, "owner_lbph_model.yml")
        # Load Haar Cascade for face detection (faster than dlib's detector on CPU)
        self.cascade_path = cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
        self.face_cascade = cv2.CascadeClassifier(self.cascade_path)
        
        self.use_fr = has_fr
        self.recognizer = None
        
        # LBPH Recognizer for fallback setup
        if not self.use_fr:
            if hasattr(cv2.face, 'LBPHFaceRecognizer_create'):
                self.recognizer = cv2.face.LBPHFaceRecognizer_create()
                if os.path.exists(self.model_file):
                    self.recognizer.read(self.model_file)
            else:
                print("Error: OpenCV contrib modules not found. Install 'opencv-contrib-python'.")

    def detect_faces_cv2(self, frame):
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        faces = self.face_cascade.detectMultiScale(gray, 1.3, 5)
        return faces, gray

    def register_owner(self):
        """Captures owner's face and saves the model/encoding."""
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            return False, "Could not open camera."

        print("Look at the camera to register your face...")
        start_time = time.time()
        collected_data = [] # Encodings (FR) or ROIs (LBPH)
        labels = [] # Labels for LBPH
        
        count = 0
        try:
            while count < 30 and (time.time() - start_time) < 60:
                ret, frame = cap.read()
                if not ret: continue

                # Draw UI instructions
                cv2.putText(frame, f"Capturing: {count}/30", (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 0), 2)
                
                faces, gray = self.detect_faces_cv2(frame)
                
                for (x, y, w, h) in faces:
                    cv2.rectangle(frame, (x, y), (x+w, y+h), (255, 0, 0), 2)
                    
                    if self.use_fr:
                        # For face_recognition, get RGB frame
                        rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                        # Use locations found by Haar cascade to speed up encoding
                        # Check bounds first
                        top, right, bottom, left = y, x+w, y+h, x
                        encodings = face_recognition.face_encodings(rgb_frame, [(top, right, bottom, left)])
                        
                        if encodings:
                            collected_data.append(encodings[0])
                            count += 1
                            time.sleep(0.2) 
                    else:
                        # For LBPH
                        roi_gray = gray[y:y+h, x:x+w]
                        if w > 100 and h > 100:
                            collected_data.append(roi_gray)
                            labels.append(0) # ID 0 for owner
                            count += 1
                            time.sleep(0.1)

                cv2.imshow('Registration - Finding You', frame)
                if cv2.waitKey(1) & 0xFF == ord('q'):
                    break
        finally:
            cap.release()
            cv2.destroyAllWindows()

        if count < 5:
            return False, "Not enough face data collected. Try creating better lighting."

        # SAVE DATA
        if self.use_fr:
            with open(self.encodings_file, "wb") as f:
                pickle.dump(collected_data, f)
            print(f"Saved {len(collected_data)} face encodings.")
        else:
            if self.recognizer:
                self.recognizer.train(collected_data, np.array(labels))
                self.recognizer.save(self.model_file)
                print(f"Trained LBPH model with {len(collected_data)} samples.")
            else:
                return False, "Recognizer not initialized."

        return True, "Owner registered successfully!"

    def verify_user(self):
        """Verifies if the person in front of the camera is the owner."""
        
        owner_encodings = []
        if self.use_fr:
            if not os.path.exists(self.encodings_file):
                return False, "No owner registered. Run setup first."
            with open(self.encodings_file, "rb") as f:
                owner_encodings = pickle.load(f)
        else:
            if not os.path.exists(self.model_file):
                return False, "No owner registered. Run setup first."
            if self.recognizer:
                self.recognizer.read(self.model_file)
            else:
                return False, "Recognizer not initialized."

        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            return False, "Camera error."

        print("Verifying...")
        start_time = time.time()
        matches = 0
        consecutive_matches = 0
        
        try:
            while (time.time() - start_time) < 15: # 15 second timeout
                ret, frame = cap.read()
                if not ret: continue

                faces, gray = self.detect_faces_cv2(frame)
                
                status_color = (0, 0, 255) # Red pending
                status_text = "Scanning..."
                
                if len(faces) == 0:
                    consecutive_matches = 0 # Reset if face lost

                for (x, y, w, h) in faces:
                    match_found = False
                    confidence_score = 0
                    
                    if self.use_fr:
                        rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                        top, right, bottom, left = y, x+w, y+h, x
                        encs = face_recognition.face_encodings(rgb_frame, [(top, right, bottom, left)])
                        
                        if encs:
                            # Compare with all stored owner encodings
                            # tolerance=0.5 is strict, default is 0.6
                            distances = face_recognition.face_distance(owner_encodings, encs[0])
                            # If any distance is very low (good match)
                            if np.min(distances) < 0.40:
                                match_found = True
                                confidence_score = (1 - np.min(distances)) * 100
                    else:
                        if self.recognizer:
                            roi_gray = gray[y:y+h, x:x+w]
                            id_, conf = self.recognizer.predict(roi_gray)
                            # LBPH: 0 is perfect match. <50 is very good. <80 is acceptable.
                            if conf < 40: 
                                match_found = True
                                confidence_score = 100 - conf
                    
                    if match_found:
                        status_color = (0, 255, 0)
                        status_text = f"MATCH ({int(confidence_score)}%)"
                        consecutive_matches += 1
                    else:
                        status_text = "Unknown Face"
                        consecutive_matches = 0
                    
                    cv2.rectangle(frame, (x, y), (x+w, y+h), status_color, 2)
                    cv2.putText(frame, status_text, (x, y-10), cv2.FONT_HERSHEY_SIMPLEX, 0.9, status_color, 2)

                cv2.imshow('Face Verification', frame)
                if cv2.waitKey(1) & 0xFF == ord('q'):
                    break
                    
                if consecutive_matches >= 3: # Require 3 consecutive positive frames
                    return True, "Access Granted"

        finally:
            cap.release()
            cv2.destroyAllWindows()
            
        return False, "Access Denied / Timeout"
