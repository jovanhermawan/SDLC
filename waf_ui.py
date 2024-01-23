import streamlit as st
import requests

def process_uploaded_file(uploaded_file):
    if uploaded_file is not None:
        # Check file type
        if uploaded_file.type == 'application/vnd.ms-excel':
            # Check file size (1 MB limit)
            if uploaded_file.size <= 1 * 1024 * 1024:
                st.success("File uploaded successfully.")
            else:
                st.error("File size exceeds the 1MB limit.")
        else:
            st.error("Invalid file format. Please upload a CSV file.")

def call_backend_api(input):
    # Replace with your Flask backend URL
    print(input)
    backend_url = "http://localhost:5000/process_data"
    try:
        response = requests.post(backend_url, data={'data': input})
        if response.status_code == 200:
            if response.text == "Request is not malicious.":
                st.success(response.text)
            else:
                st.error(response.text)
        else:
            st.error(f"Failed to call API. Status code: {response.status_code}")
        print(response.text)
    except Exception as e:
        st.error(f"An error occurred: {str(e)}")


# Button to trigger API call
        
st.write("Malicious Tool Detection")
text_input = st.text_area(label='input your string')
if st.button("Send response"):
    call_backend_api(text_input)
uploaded_file = st.file_uploader("Upload a CSV file", type=["csv"])
process_uploaded_file(uploaded_file)

