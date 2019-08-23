import json
import sys
import argparse
# Used to post the file to Nucleus
import requests


# Enter in the root URL of your Nucleus instance.
# Example https://example.nucleussec.com
NUCLEUS_ROOT_URL = "{Enter root URL of your Nucleus Instance Here}"

# Generate an API key through the Nucleus UI
API_KEY = "{Enter API Key Here}"

# Get the arachni file to parse
def open_json(inputPath):

    # Open the example file
    with open(inputPath, "r") as f:

        # Error handle when wrong file type or when the file is incorrect
        try:
            
            json_data = json.load(f)

        except Exception as e:

            print("Error with json file. Try using the correct file this time!")

            print(e)

            sys.exit(1)

        # Just in case they try to upload a json file of the wrong type        
        try:

            # Grab the endDate
            endDate = json_data["finish_datetime"]

        except:

            print("Unable to grab the key! Probably not an arachni file")

            sys.exit(1)

        # Clean up the scan date for correct Nucleus format
        endDate = endDate.split(" -")[0]

        # Grab the url of the asset which was scanned
        asset = json_data["options"]['url']

        # grab all the issues data from the json file
        issues = json_data["issues"]

        # Get ready to rummmmbbbllleeee. Need the following for top level json keys
        return asset, issues, endDate

# Used to parse the vuln data from the json file
def parse_json(outputPath, asset_info, vuln_data, scan_date):

    # Open up the new Nucleus json file
    with open(outputPath, 'w', newline='') as f:

        # Get a python dict ready to add data to
        nucleus_json_output = {}

        # Get the standard Nucleus keys ready and top level keys from earlier
        nucleus_json_output['nucleus_import_version'] = "1"
        nucleus_json_output['scan_date'] = scan_date
        nucleus_json_output["scan_tool"] = "Arachni"
        nucleus_json_output['scan_type'] = "Application"

        # Get the asset list ready (will add to the dict in one fell swoop later)
        asset_list = []

        # This we are going to add to the asset's dictionary later
        finding_list = []


        # Time to go through the arachni findings and see what we got
        for vuln in vuln_data:

            # Create a dict to throw all the finding info into. Each one will go into the findings list
            # New dictionary at the end of every finding. Trying to be polite with our mem usage
            finding_details_dict = {}

            # Get the vulnerability name
            finding_details_dict['finding_name'] = vuln["name"]

            # Get the vuln description
            finding_details_dict['finding_description'] = vuln["description"]

            # Get the vuln severity
            finding_details_dict['finding_severity'] = vuln['severity']

            # Get the http Request for the finding
            finding_details_dict['finding_http_request'] = str(vuln['request']['headers_string'] + str(vuln['request']['body']))

            # Get the http Response for the finding
            finding_details_dict['finding_http_response'] = str(vuln['response']['headers_string'] + str(vuln['response']['body']))

            # Get all the references for the good Nucleus people to not have to refer back to the arachni scanner for additional info
            finding_details_dict['finding_references'] = vuln['references']

            # Uniquely identify each of the findings with the finding digest and the asset appended to it
            finding_details_dict['finding_number'] = str(vuln["digest"])+asset_info

            # Now working on grabbing things that may or may not exist depending on the type of vuln. Want to add to json file if they exist
            # Solution
            try:

                finding_details_dict['finding_recommendation'] = vuln["remedy_guidance"]
            
            except:

                finding_details_dict['finding_recommendation'] = ""

            # Get CWEs
            try:

                finding_details_dict['finding_cve'] = 'CWE-'+str(vuln["cwe"])

            except:

                finding_details_dict['finding_cve'] = ""

            # Get the finding path. It is in the request for normal vulns and in the response for informational vulns for some reason
            try:

                finding_details_dict['finding_path'] = vuln['request']['url']

            except:

                finding_details_dict['finding_path'] = vuln['request']['url']

            # Add all the juicy details as a dictionary to the finding list. This will be repeated for all findings, so it is a list of dictionaries
            finding_list.append(finding_details_dict)

        # Create a dictionary to store all the findings from the finding list
        asset_details_dict = {}

        # Add the asset information which we got earlier (IE gotta know what we scanned)
        asset_details_dict['host_name'] = asset_info

        # Add the finding list as attached to the asset we scanned so we know what findings go on which host
        asset_details_dict['findings'] = finding_list

        #TODO: Need to add the IP address if we get it from the response
        
        # Add the asset dictionary to the asset list so Nucleus knows what to look for        
        asset_list.append(asset_details_dict)

        # Add the list to the json block for final Nucleus formatting
        nucleus_json_output['assets'] = asset_list

        # Dump dict to a json formatted file for upload to Nucleus
        json.dump(nucleus_json_output, f)

        # Return the file for posting to Nucleus
    return f


def get_args():
	parser = argparse.ArgumentParser(description="For parsing arachni files to be uploaded into Nucleus. If project ID is specified, will post the Nucleus supported file to Nucleus project.")

	# List arguments. Should only include input file and output file
	parser.add_argument('-i', '--inputfile', dest='inputFile', help="Path to whitesource xml file to parse", required=True)
	parser.add_argument('-o', '--outputfile', dest='outputFile', help="Path to csv file output", required=True)
	parser.add_argument('-#', '--project_id', dest="project_id", help="This is the project ID of the Nucleus project to which you want to post. If not specified, this script will only parse the whitesource file for manual upload.")

	# Define the arguments globally for ease of use
	global args

	args = parser.parse_args()

	return args

# Send the file to Nucleus
def post_to_nucleus(outputfile):

	# Enter the ID of the project which you wish to post to here
	PROJECT_ID = args.project_id

	# open the file to send
	with open(outputfile.name, 'rb') as f:

		# Get the final Nucleus URL to post to
		nucleus_url = str(NUCLEUS_ROOT_URL+'/nucleus/api/projects/'+PROJECT_ID+'/scans')

		print("Posted to URL:", nucleus_url)

		# Send file with proper header. Keep note of the project ID you need to send
		file_upload = requests.post(nucleus_url, files={outputfile.name: f}, headers={'x-apikey': API_KEY})	

		# Print the response from the server
		print(file_upload.content)

# The main event
if __name__ == "__main__":

	# Get the arguments
    arguments = get_args()

	# Get the input file to parse
    inputPath = arguments.inputFile

	# Get the output file to save to
    outputPath = arguments.outputFile

    asset, vuln_data, scan_date = open_json(inputPath)

    outputFile = parse_json(outputPath, asset, vuln_data, scan_date)

	# If a project ID was specified, send the file to Nucleus
    if arguments.project_id:

		# Send the newly created csv file to Nucleus if project id was specified
        post_to_nucleus(outputFile)

	# If no project ID was specified, just parse file to Nucleus  format for manual file upload
    else:

        pass
