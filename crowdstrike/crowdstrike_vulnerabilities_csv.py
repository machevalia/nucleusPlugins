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
import xmltodict
import json


# Enter in the root URL of your Nucleus instance.
# Example https://example.nucleussec.com
NUCLEUS_ROOT_URL = "{Enter root URL of your Nucleus Instance here}"

# Generate an API key through the Nucleus UI
API_KEY = "{Enter your API key from Nucleus here}"

def customParser(inputPath, outputPath):

	with open(inputPath, 'r', newline='', encoding='utf-8') as input_file:

		# Create the csv file for writing
		with open(outputPath, 'w', newline='') as csvfile:

			csvwriter = csv.writer(csvfile, delimiter=',')

			csvwriter.writerow(['nucleus_import_version', 'host_name', 'ip_address', 'scan_type', 'scan_tool', 'finding_type', 'finding_cve', 'finding_number', 'finding_output', 'finding_name', 'finding_severity', 'finding_description', 'finding_recommendation', 'scan_date', 'finding_result', 'finding_references','finding_exploitable', 'operating_system_name', 'host_location', 'finding_port'])

			# Try to parse the data. 
			try:

				findings = csv.reader(input_file, delimiter=',')

				next(findings)

				# Going to be used to check for duplicates in the input file
				csv_dupe_array = []

				for finding in findings:

					#print(finding)

					# Get the line ready to write to output file
					csv_line = []

					# Grab the values we need
					try:

						severity = finding[11]

						finding_name = finding[8]

						asset_name = finding[0].strip()

						asset_ip = finding[1]

						os = finding[3]

						finding_number = finding[8]

						finding_output = finding[7]

						# Used to add a link to the description field in Nucleus and pretty display
						description = finding[9] + "\n\n <a href='" + finding[18] + "target="'_blank'">" + finding[18] + "</a>"

						scan_date = finding[12]

						solution = finding[21] + "\n\n" + finding[22] 

						finding_cve = finding[8]

						if finding[26] == '0':

							finding_exploitable = 'false'

						else:

							finding_exploitable = 'true'

						references = "Exploit Status:" + finding[27] + "," + "Exploit Status Value:" + finding[26]

						asset_domain = finding[6]

						# Used to check for duplicates. Alter this if you want to change how Nucleus tracks instances of vulns
						fjk = asset_name + finding_number

					except Exception as e:

						print(e)

					csv_line.extend(['1', asset_name, asset_ip, 'Host', 'Crowdstrike', 'Vuln', finding_cve, finding_number, finding_output, finding_name, severity, description, solution, scan_date, 'Failed', references, finding_exploitable, os, asset_domain, 0])

					#print(csv_line)

					# Use this to deduplicate the findings from crowdstrike which are the same for some reason
					if fjk in csv_dupe_array:

						pass

					else:

						csvwriter.writerow(csv_line)

						csv_dupe_array.append(fjk)



			except Exception as e:

				print("Error:", e)
		

def get_args():
	parser = argparse.ArgumentParser(description="For parsing whitesource files to be uploaded into Nucleus. If project ID is specified, will post the Nucleus supported file to Nucleus project.")

	# List arguments. Should only include input file and output file
	parser.add_argument('-i', '--inputfile', dest='inputFile', help="Path to trustwave xml file", required=True)
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



if __name__ == "__main__":

	# Get the arguments
	arguments = get_args()

	# Get the input file to parse
	inputPath = arguments.inputFile

	# Get the output file to save to
	outputPath = arguments.outputFile

	# Start the parsing and csv writing
	outputfile = customParser(inputPath, outputPath)

	#print(outputfile.name)

	# If a project ID was specified, send the file to Nucleus
	if arguments.project_id:

		# Send the newly created csv file to Nucleus if project id was specified
		post_to_nucleus(outputfile)

	# If no project ID was specified, just parse file to Nucleus  format for manual file upload
	else:

		pass
