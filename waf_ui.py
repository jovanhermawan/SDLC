import streamlit as st
import requests



def call_backend_api(input):
    # Replace with your Flask backend URL
    print(input)
    # backend_url = "http://localhost:5000/api/action"


    # try:
    #     response = requests.get(backend_url)
    #     if response.status_code == 200:
    #         st.success("API call successful!")
    #     else:
    #         st.error(f"Failed to call API. Status code: {response.status_code}")
    # except Exception as e:
    #     st.error(f"An error occurred: {str(e)}")


# Button to trigger API call
        
st.write("Malicious")
text_input = st.text_input(label='input your string')
if st.button("Send response"):
    call_backend_api(text_input)

