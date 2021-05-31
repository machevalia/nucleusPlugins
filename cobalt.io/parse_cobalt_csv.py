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

# Enter in the root URL of your Nucleus instance WITHOUT the trailing slash.
# Example https://example.nucleussec.com
NUCLEUS_ROOT_URL = "{Enter root URL of your Nucleus Instance here}"
# Generate an API key through the Nucleus UI
API_KEY = "{Enter your API key from Nucleus here}"

def customParser(inputPath, outputPath, adjustSeverity):

	with open(inputPath, 'r', newline='', encoding='utf8') as input_file:

		# Create the csv file for writing
		with open(outputPath, 'w', newline='') as csvfile:

			csvwriter = csv.writer(csvfile, delimiter=',')

			#TODO: modularize/object orient the regex IP matching. Currently used 3 times inline
			# Set up regex for IP address matching later in this function
			simple_ip_regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"

			csvwriter.writerow(['nucleus_import_version', 'host_name', 'ip_address', 'scan_type', 'scan_tool', 'finding_type', 'finding_cve', 'finding_number', 'finding_output', 'finding_name', 'finding_severity', 'finding_description', 'finding_recommendation', 'scan_date', 'finding_result', 'finding_references','finding_exploitable', 'operating_system_name', 'host_location', 'finding_port'])

			# Start parsing the data. 

			findings = csv.reader(input_file, delimiter=',')

			#print(findings)

			# Skip the first line headers
			next(findings)

			# Read each line of the csv input file for parsing
			for finding in findings:

				#print(finding)

				# Get the line ready to write to output file
				csv_line = []

				# Check to see if user wants to adjust the severity of cobalt findings to map higher up the Nucleus scale
				if adjustSeverity == True:

					# All the new severity mappings for the severity in Cobalt to Nucleus severity
					if finding[7] == 'low':

						severity = 'Medium'

					elif finding[7] == 'medium':

						severity = 'High'

					elif finding[7] == 'high':

						severity = 'Critical'

					# Set a default severity
					else:

						severity = 'low'

				# Map the cobalt severity directly to the Nucleus severity
				else:

					# Check to see if severity field is populated
					if finding[7] == '':

						# If not, set default to low
						severity = "low"

					# Severity exists so use that
					else:

						severity = finding[7].capitalize()
				
				#Try to set the variables for the csv line
				try:

					finding_name = finding[2].replace("'","")
					finding_number = finding[2].replace("'","")
					finding_output = finding[8].replace("'","")
					description = finding[9].replace("'","") + "\n\n" + finding_output + "\n\n <a href='" + finding[17] + "' target="'_blank'">" + finding[17] + "</a>" 
					scan_date = finding[4].replace(" UTC", '')
					solution = finding[12].replace("'","")
					references = "Reporter:" + finding[18] + "," + "Researcher URL:" + finding[19]

					#print(finding_name, finding_output, description, scan_date, solution, references)

				except Exception as e:

					print(e)

				#Asset list empty for use in detecting when multiple assets or no assets are defined
				assets_list = []

				# Try to get the asset names on each line (There might not be any asset associated with the vuln)
				if finding[5] == '':

					print("No asset defined for this vuln, setting to general asset")

					asset_name = "General Asset"

					csv_line = ['1', asset_name, '', 'Host', 'Cobalt.io', 'Vuln', '', finding_number, finding_output, finding_name, severity, description, solution, scan_date, 'Failed', references, '', '', '', 0]
				
					csvwriter.writerow(csv_line)

				# There are assets defined separated by comma in a single cell
				else:
					
					assets_list = finding[5].replace("'","").split(",")

					#print(assets_list)

				if assets_list != []:
				
					try:
					
						# Extract the assets from the rows with multiple assets
						# Also should handle single assets
						for asset in assets_list:

							#print(asset)

							# Check assets which DO NOT have http in the front to validate asset type
							if asset.find("http") == -1:

								asset_type = "Host"

								# Check to see if it has a port associated with it
								# Grab the ip address for validation
								asset_ip = asset.split(":")[0]

								# Grab the port info for the csv file
								finding_port = asset.split(":")[-1]

								# Run finding_port through the IP regex above to determine if it is a valid port or not
								if re.search(simple_ip_regex, finding_port):

									# if it is a valid IP, then we should ignore the finding_port because split was not successful
									finding_port = ''

								# If port is not a valid IP, then map the port value to the finding_port field
								else:

									finding_port = finding_port

								# Asset name is constant minus the port if port exists
								asset_name = asset.replace(":" + finding_port, '')

								check_for_ip = asset_ip

							# There was http or https:, start testing to see if it is an application
							#NOTE: cannot skip the regex because there can be random values in this field that are neither http based or IP based
							else:

								# Grab the string after the http method in order to validate if it's an IP
								ip_port = asset.split("://")[-1]

								#print(ip_port)

								# Grab the ip address for validation
								check_for_ip = ip_port.split(":")[0]

								# Grab the port info for the csv file
								finding_port_raw = ip_port.split(":")[-1]

								finding_port = finding_port_raw.replace('/', '')

								# Run through the basic IP regex above to determine if the finding port is an IP or not
								if re.search(simple_ip_regex, finding_port):

									#print("port is an IP: ", finding_port)

									# if it is a valid IP, then we should set the IP address on the asset record
									finding_port = ''

								# If it is not a valid IP, then return the port correctly to the finding_port field
								else:

									finding_port = finding_port

									#print(check_for_ip, finding_port)

								# Run the IP through the basic regex above to check if that is an IP
								if re.search(simple_ip_regex, check_for_ip):

									#print("Asset is an IP: ", check_for_ip)

									# If it returned a valid IP through the regex, then mark it as a host asset
									asset_type = "Host"

									# if it is a valid IP, then we should set the IP address on the asset record
									asset_ip = check_for_ip

								# If it is not a valid IP, then return it was an application url type asset
								else:

									#print(asset)

									# Set asset fields to App defaults in this situation
									asset_type = "Application"
									asset_ip = ''
									finding_port = ''

								# No matter what happens, the asset name will remain the full asset name string minus the port
								asset_name = asset.replace(":" + finding_port_raw, '')

							# Handle attached file host list (add to general asset)
							if asset_name == "see attached file with affected hosts.":

								# Set some blank values
								asset_ip = ''
								asset_name = "General Asset"
								finding_port = '0'

							else:

								pass


							# Write a row for each asset in the cell coming from cobalt
							csv_line = ['1', asset_name, asset_ip, asset_type, 'Cobalt.io', 'Vuln', '', finding_number, finding_output, finding_name, severity, description, solution, scan_date, 'Failed', references, '', '', '', finding_port]

							#csv_line.extend(['1', asset_name, check_for_ip, asset_type, 'Cobalt.io', 'Vuln', '', finding_number, finding_output, finding_name, severity, description, solution, scan_date, 'Failed', references, '', '', '', finding_port])
							csvwriter.writerow(csv_line)

					except Exception as e:

						print("Error getting list of assets:" + e)

				# Row has already been written to csv, make sure to do nothing in this case (if asset_list is empty)
				else:

					pass

		csvfile.close()

		# Send output file back to main function
		return csvfile

		


def get_args():
	parser = argparse.ArgumentParser(description="For parsing whitesource files to be uploaded into Nucleus. If project ID is specified, will post the Nucleus supported file to Nucleus project.")

	# List arguments. Should only include input file and output file
	parser.add_argument('-i', '--inputfile', dest='inputFile', help="Path to whitesource xml file to parse", required=True)
	parser.add_argument('-o', '--outputfile', dest='outputFile', help="Path to csv file output", required=True)
	parser.add_argument('-#', '--project_id', dest="project_id", help="This is the project ID of the Nucleus project to which you want to post. If not specified, this script will only parse the whitesource file for manual upload.")
	parser.add_argument('-s', '--severity_adjust', dest='adjustSeverity', help="This will adjust the severities from cobalt up a level in the Nucleus scale. Default is to show the Cobalt.io severities", required=False, action='store_true')



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

	# Determine if user wants to adjust cobalt severity.
	adjustSeverity = arguments.adjustSeverity

	#Print to cli so user has feedback
	print("File received, parsing contents")

	# Start the parsing and csv writing
	outputfile = customParser(inputPath, outputPath, adjustSeverity)

	# If a project ID was specified, send the file to Nucleus
	if arguments.project_id:
		
		print("Parsing complete. Sending to specified Nucleus project")

		# Send the newly created csv file to Nucleus if project id was specified
		post_to_nucleus(outputfile)

	# If no project ID was specified, just parse file to Nucleus  format for manual file upload
	else:

		print("Parsing complete. Success!")
