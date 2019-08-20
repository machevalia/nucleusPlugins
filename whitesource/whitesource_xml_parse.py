#!/usr/bin/python3.7
__author__ = "Nucleus Security"
__license__ = "MIT License"
__version__ = "0.0"

import xml.etree.ElementTree as ET
import csv
import argparse
import sys

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

		except Exception as e:

			print("Error, probably bad xml document. Check that you are trying to parse the correct doc type")

			print("Error was the following:", e)


def get_args():
	parser = argparse.ArgumentParser(description="For parsing whitesource files to be uploaded into Nucleus")

	# List arguments. Should only include input file and output file
	parser.add_argument('-i', dest='inputFile', help="Path to whitesource xml file to parse", required=True)
	parser.add_argument('-o', dest='outputFile', help="Path to csv file output", required=True)

	# Define the arguments globally for ease of use
	global args

	args = parser.parse_args()

	return args


if __name__ == "__main__":

	# Get the arguments
	arguments = get_args()

	# Get the input file to parse
	inputPath = arguments.inputFile

	# Get the output file to save to
	outputPath = arguments.outputFile

	# Start the parsing and csv writing
	customParser(inputPath, outputPath)


