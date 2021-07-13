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
    with open(inputPath, 'r', newline='', encoding='utf8') as input_file:
        findings = csv.reader(input_file)

        # Create the csv file for writing
        with open(outputPath, 'w', newline='') as output_file:

            # write headers on output file
            csvwriter = csv.writer(output_file, delimiter=',')
            csvwriter.writerow(['nucleus_import_version', 'host_name', 'scan_date', 'scan_type', 'scan_tool',\
                                'finding_number', 'finding_name', 'finding_severity', 'finding_type', 'finding_cve',\
                                'finding_description', 'finding_exploitable', 'finding_path', 'finding_recommendation',\
                                'finding_references', 'finding_result', 'asset_info'])

            # skip first line of csv headers
            next(findings)

            # iterate through each row in findings and map to nucleus fields
            for finding in findings:
                csv_line = []
                host_name = finding[1]
                scan_date = datetime.strptime(finding[42], '%m/%d/%y')
                #find_num = finding[7] + "-" + finding[2]
                find_num = finding[7]
                find_name = finding[7]
                if (finding[39] != "negligible"):
                    find_sev = finding[39]
                else:
                    find_sev = "informational"
                find_cve = finding[7]
                find_descr = finding[27]
                find_path = finding[4]
                if (finding[34] == "patch_available"):
                    # provide patch information
                    find_rec = finding[34] + "\n" + "Patch to lastest version: " + finding[25]
                else:
                    # no patch available
                    find_rec = finding[34]
                # os and version mapping
                if len(finding[3]) > 1:
                    os_idx = re.search(r"\d", finding[3]).span()[0] # get index of version in OS string
                    os_name = finding[3][:(os_idx-1)]
                    os_version = finding[3][os_idx:]
                else:
                    os_name = ""
                    os_version = ""
                # invoke reference builder
                find_refs = create_refs(finding)
                # generate asset info
                asset_info = ""
                if (finding[0]): asset_info = asset_info + "aqua.registry:" + finding[0]
                sha = finding[2]
                if (finding[2]): asset_info = asset_info + ";aqua.image_digest:" + sha.replace("sha256:", "")
                # create csv line array and write to output file
                csv_line = ['1', host_name, scan_date, 'Container Image', 'Aqua', find_num, find_name, find_sev, 'Vuln', \
                            find_cve, find_descr, "True", find_path, find_rec, find_refs, "Failed", asset_info]
                csvwriter.writerow(csv_line)

            output_file.close()
            return output_file

def create_refs(finding):

    # populate ref params
    cvss_v3_score = finding[21]
    cvss_v3_vec = finding[22]
    cvss_v2_score = finding[18]
    cvss_v2_vec = finding[19]
    publish_date = finding[8]
    exploit_type = finding[45]
    exploit_avail = finding[43]
    temporal_vector = finding[44]

    # create refs string
    refs = ""
    if (cvss_v3_score): refs = refs + "CVSS V3 Score: " + cvss_v3_score
    if (cvss_v3_vec): refs = refs + ",CVSS V3 Vector: " + cvss_v3_vec
    if (cvss_v2_score): refs = refs + ",CVSS V2 Score: " + cvss_v2_score
    if (cvss_v2_vec): refs = refs + ",CVSS V2 Vector: " + cvss_v2_vec
    if (publish_date): refs = refs + ",Publish Date: " + publish_date
    if (exploit_type): refs = refs + ",Exploit Type: " + exploit_type
    if (exploit_avail): refs = refs + ",Exploit Available: " + exploit_avail
    if (temporal_vector): refs = refs + ",Temporal Vector: " + temporal_vector

    return refs

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
