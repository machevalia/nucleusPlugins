#!/usr/bin/python3.7
__author__ = "Nucleus Security"
__license__ = "MIT License"
__version__ = "0.1"

#Used for writing to csv
import csv
# Used for arguments
import argparse
# Used to post the file to Nucleus
import requests
import re 
import ipaddress

# Enter in the root URL of your Nucleus instance WITHOUT the trailing slash.
# Example https://example.nucleussec.com
NUCLEUS_ROOT_URL = "{Enter root URL of your Nucleus Instance here}"
# Generate an API key through the Nucleus UI
API_KEY = "{Enter your API key from Nucleus here}"

def customParser(inputPath, outputPath):

	with open(inputPath, 'r', newline='', encoding='utf8') as input_file:

		# Create the csv file for writing
		with open(outputPath, 'w', newline='') as csvfile:

			csvwriter = csv.writer(csvfile, delimiter=',')
			csvwriter.writerow(['nucleus_import_version', 'host_name', 'ip_address', 'scan_type', 'scan_tool', 'asset_info', 'operating_system_name', 'host_location'])

			# Start parsing the data. 
			assets = csv.reader(input_file, delimiter=',')

			# Skip the first line headers
			next(assets)

			# Read each line of the csv input file for parsing
			for asset in assets:

				# Get the line ready to write to output file
				csv_line = []
				
				#Try to set the variables for the csv line
				try:

					asset_name = asset[0]
					asset_ip = asset[2]
					asset_os = asset[3]
					asset_location = asset[6]
					
					asset_metadata = "flexera.criticality" + asset[13] + ";flexera.virtualhost:" + asset[4] + ";flexera.serialnumber:" + asset[1] + ";flexera.environment:" + asset[5] + ";flexera.location:" + asset[6] + ";flexera.pci:" + asset[7] + ";flexera.flexera_id:" + asset[10] + ";flexera.application:" + asset[11] + ";flexera.alias:" + asset[12] + ";flexera.managing_director:" + asset[13] + ";flexera.application_owner:" + asset[14] + ";flexera.architect:" + asset[15]

				except Exception as e:

					print(e)



				# Write a row for each asset in the cell coming from cobalt
				csv_line = ['1', asset_name, asset_ip, 'Host', 'Asset', asset_metadata, asset_os, asset_location]

				#csv_line.extend(['1', asset_name, check_for_ip, asset_type, 'Cobalt.io', 'Vuln', '', asset_number, asset_output, asset_name, severity, description, solution, scan_date, 'Failed', references, '', '', '', asset_port])
				csvwriter.writerow(csv_line)

		csvfile.close()

		# Send output file back to main function
		return csvfile

		


def get_args():
	parser = argparse.ArgumentParser(description="For parsing whitesource files to be uploaded into Nucleus. If project ID is specified, will post the Nucleus supported file to Nucleus project.")

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

		if file_upload.status_code == 404:

			print("You probably entered the wrong url. Check to make sure the last slash '/' has been removed from the NUCLEUS_ROOT_URL")

		else:

			pass



if __name__ == "__main__":

	# Get the arguments
	arguments = get_args()

	# Get the input file to parse
	inputPath = arguments.inputFile

	# Get the output file to save to
	outputPath = arguments.outputFile

	#Print to cli so user has feedback
	print("File received, parsing contents")

	# Start the parsing and csv writing
	outputfile = customParser(inputPath, outputPath)

	# If a project ID was specified, send the file to Nucleus
	if arguments.project_id:
		
		print("Parsing complete. Sending to specified Nucleus project")

		# Send the newly created csv file to Nucleus if project id was specified
		post_to_nucleus(outputfile)

	# If no project ID was specified, just parse file to Nucleus  format for manual file upload
	else:

		print("Parsing complete. Success!")
