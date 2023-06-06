#!/usr/bin/python3
import os
import tempfile
import subprocess
import requests
from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

# Enter the URL of your Nucleus instance and API key
NUCLEUS_ROOT_URL = "<YOUR NUCLEUS URL"
API_KEY = "YOUR API KEY"

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # Check if the file is present in the request
        if 'file' not in request.files:
            return render_template('index.html', error='No file selected')

        # Get the file from the request
        file = request.files['file']

        # Check if a project name is selected
        project_name = request.form.get('project')

        # Create a temporary directory to store the uploaded file
        with tempfile.TemporaryDirectory() as temp_dir:
            # Save the file to the temporary directory
            file_path = os.path.join(temp_dir, file.filename)
            file.save(file_path)

            # Convert Beagle XML to Nucleus XML using the beagle_xml.py script
            output_file_path = os.path.join(temp_dir, 'nucleus_output.xml')
            conversion_command = ['python', 'beagle_xml.py', file_path, output_file_path]
            subprocess.run(conversion_command)

            # Post the Nucleus XML file to the Nucleus project
            if project_name:
                post_to_nucleus(output_file_path, project_name)

            # Redirect back to the index page
            return redirect(url_for('index'))

    # Render the upload form
    projects = get_projects()
    return render_template('index.html', projects=projects)

@app.route('/', methods=['GET'])
def index():
    projects = get_projects()
    return render_template('index.html', projects=projects)

def get_projects():
    url = f"{NUCLEUS_ROOT_URL}/nucleus/api/projects"
    headers = {'accept': 'application/json', 'x-apikey': API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        project_data = response.json()
        return [project['project_name'] for project in project_data]
    else:
        print(f"Failed to fetch projects. Error: {response.text}")
        return []

def post_to_nucleus(file_path, project_name):
    # Get the project ID based on the project name
    project_id = get_project_id(project_name)
    if project_id is None:
        print(f"Project '{project_name}' not found")
        return

    # Get the Nucleus upload URL
    nucleus_url = f"{NUCLEUS_ROOT_URL}/nucleus/api/projects/{project_id}/scans"

    # Open the file to send
    with open(file_path, 'rb') as f:
        try:
            # Send the file with the proper header and API key
            file_upload = requests.post(nucleus_url, files={file_path: f}, headers={'x-apikey': API_KEY})
            
            # Print the response from the server
            print(file_upload.content)

        except Exception as e:
            print("Unable to post file to Nucleus. Try checking your Nucleus URL and project ID")
            print("Error:", e)

def get_project_id(project_name):
    url = f"{NUCLEUS_ROOT_URL}/nucleus/api/projects"
    headers = {'accept': 'application/json', 'x-apikey': API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        project_data = response.json()
        for project in project_data:
            if project['project_name'] == project_name:
                return project['project_id']
    else:
        print(f"Failed to fetch projects. Error: {response.text}")
    return None

if __name__ == "__main__":
    app.run()
