#!/usr/bin/python3.7
__author__ = "Nucleus Security"
__license__ = "MIT License"
__version__ = "0.1"

# Used for parsing the xml whitesource file
import xml.etree.ElementTree as ET
#Used for writing to csv
import csv
# Used for arguments
import argparse
# Used to post the whitesource file to Nucleus
import requests


# Enter in the root URL of your Nucleus instance.
# Example https://example.nucleussec.com
NUCLEUS_ROOT_URL = "{Enter root URL of your Nucleus Instance here}"

# Generate an API key through the Nucleus UI
API_KEY = "{Enter your API key from Nucleus here}"



def customParser(inputPath, outputPath):

	# Create the csv file for writing
	with open(outputPath, 'w', newline='') as csvfile:

		csvwriter = csv.writer(csvfile, delimiter=',')

		csvwriter.writerow(['nucleus_import_version', 'host_name', 'scan_type', 'scan_tool', 'finding_type', 'finding_cve', 'finding_number', 'finding_name', 'finding_severity', 'finding_description', 'finding_solution', 'finding_output', 'finding_path', 'finding_result'])

		# Used to verify paths and differentiate between two of the same tag
		path = []
		
		# Try to parse the data. 
		try:

			# Loop to stream data from the xml file into a csv
			for event, elem in ET.iterparse(inputPath, events=("start", "end")):

				# Used to check the paths later
				if event == 'start':

					# Used to verify where in the hierarchy you are when finding certain tags in a stream
					# Need to have a store because we are streaming the data instead of finding all
					# Necessary in case of really big xml files for mem use
					path.append(elem.tag)

				# Where we start building parsing for each item we want
				elif event == 'end':

					csv_line = []
			
					# iterate through the tags in the xml until you get to a severity tag
					if elem.tag == 'severity':

						severity = elem.text.strip()


					# Check for the affected packge from xml file
					if elem.tag == 'library':

						library = elem.text.strip()


					# Check the vuln description and the top fix
					if elem.tag == 'description':

						if 'topFix' not in path:

							# Strip is for cleaning the newlines off the output before writing into the csv file
							vulnDescription = elem.text.strip()

						else:

							# Strip is for cleaning the newlines off the output before writing into the csv file
							solutionDescription = elem.text.strip()

					# Get both the assets affected and the name of the vuln
					# Also used to get the affected CVEs
					if elem.tag == 'name':

						# Get vuln first and assign to variable so can add to assets
						if 'name' and 'occurrences' not in path:

							vulnName = elem.text.strip()
					
						# Get the assets affected and add vuln name to asset
						elif 'project' not in path:

							host_name = elem.text.strip()

						

						else:
			
							finding_path = elem.text.strip()

							# Write the csv line for every finding path
							csv_line = ['1', host_name, "Application", "WhiteSource", "Vuln", vulnName, vulnName+host_name, vulnName+": "+library, severity, vulnDescription, solutionDescription, library, finding_path, 'FAILED']


					if csv_line != []:

						csvwriter.writerow(csv_line)

						# For testing the output of each line being written into the csv file
						# print("Wrote line into csv file! ", csv_line)

					else:

						pass
					
					# Reset the path for the next piece of the streamed xml file
					path.pop()

			# Get the csvfile to send to Nucleus
			return csvfile

		except Exception as e:

			print("Error, probably bad xml document. Check that you are trying to parse the correct doc type")

			print("Error was the following:", e)


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



if __name__ == "__main__":

	# Get the arguments
	arguments = get_args()

	# Get the input file to parse
	inputPath = arguments.inputFile

	# Get the output file to save to
	outputPath = arguments.outputFile

	# Start the parsing and csv writing
	outputfile = customParser(inputPath, outputPath)

	print(outputfile.name)

	# If a project ID was specified, send the file to Nucleus
	if arguments.project_id:

		# Send the newly created csv file to Nucleus if project id was specified
		post_to_nucleus(outputfile)

	# If no project ID was specified, just parse file to Nucleus  format for manual file upload
	else:

		pass