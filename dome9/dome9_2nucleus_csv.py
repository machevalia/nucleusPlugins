# Used for writing to csv
import csv
# Used for arguments
import argparse
# Used to post the file to Nucleus
import requests
from datetime import datetime
import re

# Enter in the root URL of your Nucleus instance WITHOUT the trailing slash.
# Example https://example.nucleussec.com
NUCLEUS_ROOT_URL = "{Enter root URL of your Nucleus Instance here}"
# Generate an API key through the Nucleus UI
API_KEY = "{Enter your API key from Nucleus here}"


def customParser(inputPath, outputPath):
    with open(inputPath, 'r', newline='', encoding = 'cp1252') as input_file:
        findings = csv.reader(input_file)

        # Create the csv file for writing
        with open(outputPath, 'w', newline='\n') as output_file:

            # write headers on output file
            csvwriter = csv.writer(output_file, delimiter=',')
            csvwriter.writerow(['nucleus_import_version', 'host_name', 'scan_type', 'scan_tool', \
                                'finding_number', 'finding_name', 'finding_severity', 'finding_type', \
                                'finding_description', 'finding_exploitable', 'finding_recommendation', \
                                'finding_result', 'asset_info'])

            # skip first line of csv headers
            next(findings)

            # iterate through each row in findings and map to nucleus fields
            row = 1
            for finding in findings:
                if finding == []:
                    continue
                csv_line = []
                if finding[8] != "":
                    host_name = finding[8]
                else:
                    host_name = finding[0]
                find_num = finding[3]
                find_name = finding[3] + " - "  + finding[2]
                find_sev = finding[4]
                find_descr = finding[7] + "\n\n" + finding[5]
                find_rec = finding[6]

                # generate asset info
                asset_info = ""
                asset_info = asset_info + "dome9.account_name:" + finding[0]
                asset_info = asset_info + ";dome9.aws_account_id:" + finding[1]

                # create csv line array and write to output file
                csv_line = ['1', host_name, 'Host', 'Dome9', find_num, find_name, find_sev, 'Vuln', \
                            find_descr, "False", find_rec, "Failed", asset_info]
                csvwriter.writerow(csv_line)
                row += 1

            output_file.close()
            return output_file

def get_args():
    parser = argparse.ArgumentParser(
        description="For parsing whitesource files to be uploaded into Nucleus. If project ID is specified, will post the Nucleus supported file to Nucleus project.")

    # List arguments. Should only include input file and output file
    parser.add_argument('-i', '--inputfile', dest='inputFile', help="Path to whitesource xml file to parse",
                        required=True)
    parser.add_argument('-o', '--outputfile', dest='outputFile', help="Path to csv file output", required=True)
    parser.add_argument('-#', '--project_id', dest="project_id",
                        help="This is the project ID of the Nucleus project to which you want to post. If not specified, this script will only parse the whitesource file for manual upload.")

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
        nucleus_url = str(NUCLEUS_ROOT_URL + '/nucleus/api/projects/' + PROJECT_ID + '/scans')

        print("Posted to URL:", nucleus_url)

        # Send file with proper header. Keep note of the project ID you need to send
        file_upload = requests.post(nucleus_url, files={outputfile.name: f}, headers={'x-apikey': API_KEY})

        # Print the response from the server
        print(file_upload.content)

        if file_upload.status_code == 404:

            print(
                "You probably entered the wrong url. Check to make sure the last slash '/' has been removed from the NUCLEUS_ROOT_URL")

        else:

            pass


if __name__ == "__main__":

    # Get the arguments
    arguments = get_args()

    # Get the input file to parse
    inputPath = arguments.inputFile

    # Get the output file to save to
    outputPath = arguments.outputFile

    # Print to cli so user has feedback
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
