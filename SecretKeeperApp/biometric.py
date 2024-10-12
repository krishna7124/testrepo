import cv2
import numpy as np
import face_recognition
from PIL import Image
import streamlit as st
from database import create_connection
from mysql.connector import Error
import logging
import base64
from io import BytesIO


def capture_and_store_biometric_data(username, captured_image):
    """Capture and store biometric data using Streamlit camera input with red/green indicator."""
    encodings = []
    st.write("Capture your biometric data using the camera below. The box will turn green when your face is detected.")

    # Convert the captured image to RGB
    image = Image.open(captured_image)
    rgb_frame = np.array(image)

    # Detect face locations
    face_locations = face_recognition.face_locations(rgb_frame)

    if face_locations:
        # If face is detected, show green border and allow capture
        st.success("Face detected! Press the capture button.")
        border_color = "green"
        # Convert the captured image to Base64 for display
        buffered = BytesIO()
        image.save(buffered, format="PNG")
        img_base64 = base64.b64encode(buffered.getvalue()).decode()

        # Display the captured image with the green border
        st.markdown(
            f'<div style="border: 5px solid {
                border_color}; width: 400; height: 400; display: flex; justify-content: center; align-items: center;">'
            f'<img src="data:image/png;base64,{
                img_base64}" alt="Captured Image" style="max-width: 100%; max-height: 100%;"></div>',
            unsafe_allow_html=True,
        )

        # Store the encoding for the detected face
        face_encoding = face_recognition.face_encodings(
            rgb_frame, face_locations)[0]
        encodings.append(face_encoding)

        st.success(f"Image Captured Successfully!")

    if encodings:
        # Average the encodings for better accuracy
        avg_encoding = np.mean(encodings, axis=0)
        logging.info("Biometric data captured successfully.")
        return avg_encoding.tobytes()  # Convert numpy array to bytes

    st.error("⚠️ No face detected. Please try again.")
    return None


def biometric_verification(username, captured_image):
    """Verify user biometric data with red/green face detection indicator."""
    connection = create_connection()
    if connection is None:
        return False

    try:
        cursor = connection.cursor()
        cursor.execute(
            "SELECT biometric_data FROM users WHERE username = %s", (username,))
        result = cursor.fetchone()

        if result:
            # Convert bytes back to numpy array
            stored_face_encoding = np.frombuffer(result[0], dtype=np.float64)

            st.write(
                "Biometric verification in progress. The box will turn green when your face is detected.")

            # Convert the captured image to RGB
            image = Image.open(captured_image)
            rgb_frame = np.array(image)

            # Detect face locations
            face_locations = face_recognition.face_locations(rgb_frame)

            if face_locations:
                # If face is detected, show green border
                st.success("Face detected! Verifying...")
                face_detected = True
                border_color = "green"
            else:
                # If no face is detected, show red border
                st.error("No face detected. Please adjust your position.")
                face_detected = False
                border_color = "red"

            # Convert the captured image to Base64 for display
            buffered = BytesIO()
            image.save(buffered, format="PNG")
            img_base64 = base64.b64encode(buffered.getvalue()).decode()

            # Display the captured image with the red/green border
            st.markdown(
                f'<div style="border: 5px solid {
                    border_color}; width: 400; height: 400; display: flex; justify-content: center; align-items: center;">'
                f'<img src="data:image/png;base64,{
                    img_base64}" alt="Captured Image" style="max-width: 100%; max-height: 100%;"></div>',
                unsafe_allow_html=True,
            )

            if face_detected:
                # Extract face encoding
                face_encoding = face_recognition.face_encodings(
                    rgb_frame, face_locations)[0]

                # Calculate the face distance
                face_distance = face_recognition.face_distance(
                    [stored_face_encoding], face_encoding)
                match_threshold = 0.4  # Use a stricter threshold for comparison

                if face_distance < match_threshold:
                    st.success("✅ Biometric verification successful.")
                    return True
                else:
                    st.error("❌ Biometric verification failed. Please try again.")
        else:
            st.error("❌ No biometric data found for the user.")

    except Error as e:
        logging.error(f"Error retrieving biometric data: {e}")
    finally:
        if connection:
            connection.close()

    return False
