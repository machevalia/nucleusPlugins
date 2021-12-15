#!/usr/bin/env python3
import requests
import json
import pandas as pd
import logging, platform
import os

# Global variables
# Enter in the root URL of your Nucleus instance.
# Example https://example.nucleussec.com
NUCLEUS_ROOT_URL = "<Enter url (ex: https://example.example.com)" 
# Generate an API key through the Nucleus UI
API_KEY = "<Nucleus API key here>"
PROJECT_ID = '<Nucleus project id here>'

# Generate an API key through the VDoo UI
VDOO_KEY = '<Enter vdoo api key here>'
VDOO_ROOT_URL = "https://prod.vdoo.io"

headers = { 'Authorization': 'Token ' + VDOO_KEY,
            'content-type': 'application/json'}

# Get hostname class for injecting into the logs
class HostnameFilter(logging.Filter):
    hostname = platform.node()

    def filter(self, record):
        record.hostname = HostnameFilter.hostname
        return True

# Define the severity levels to correspond to Vdoo
def severity(x):
    if x >= 9.0:
        return("Critical")
    elif 9.0 > x >= 7.0:
        return("High")
    elif 7.0 > x >= 4.0:
        return("Medium")
    elif x > 0.1:
        return("Low")
    else:
        return("Informational")

# Get the list of images
def get_images(headers):
    api = requests.get(VDOO_ROOT_URL + '/v3/images', headers=headers)
    images = json.loads(api.text)
    return images

def get_vulns(url):

    # also this would be a good place to build in error handling. look for error, return empty scan
    response = requests.get(url, headers=headers)
    a = json.loads(response.text)

    #print(a)
    #print('')
    try:
        a1 = pd.json_normalize(a, record_path=['results'])
    except:
        # load in a single line if we get no data
        a1 = pd.DataFrame({'id': 0, 'cve_id': '0', 'component': '0', 'component_version': '0', 'attack_vector': 'LOCAL', 'cvss': {'cvss_score': 0, 'cvss_version': '2.0'}, 'cwe': {'cwe_id': '0', 'cwe_name': 'None'}, 'impact': 'low', 'number_of_exploits': 0, 'number_of_attacks': 0, 'cvss.cvss_score': 0, 'status': 'to_fix', 'description': 'No scan data available'})
        return a1
    if a['next'] != None:
        #print(a)
        b1 = get_vulns(a['next'])
        c1 = pd.concat([a1, b1])
        return c1
    else:
        return a1

def exploits(a):
    if a < 1:
        return "false"
    else:
        return "true"

def get_image_vulns(images, headers):

    for i in images['results']:
        #scan = requests.get(VDOO_ROOT_URL + '/v3/images/' + i['image_uuid'] + '/cves/', headers=headers)
        #vdoo = json.loads(scan.text)
        logger.debug("Pulling Vdoo cves for {}".format(i))
        vdoodf = get_vulns(VDOO_ROOT_URL + '/v3/images/' + i['image_uuid'] + '/cves/') # this one's recursive, should handle paging

        logger.debug("Pulling Vdoo cve analyses for {}".format(i))
        analysis = requests.get(VDOO_ROOT_URL + '/v3/images/' + i['image_uuid'] + '/analysis_results/', headers=headers)
        image = json.loads(analysis.text)
        # name, version, os_type/os_version, distro/distro_version

        logger.debug("Pulling Vdoo artifacts for {}".format(i))
        artifact = requests.get(VDOO_ROOT_URL + '/v3/artifacts/' + str(i['artifact_id']), headers=headers)
        asset = json.loads(artifact.text)

        #print('artifact: ')
        print(asset)

        nucleusdf = pd.DataFrame()
        #nucleusdf['finding_exploitable'] = vdoodf['number_of_exploits']
        # need to convert 0 to 'False', nonzero to 'True'
        nucleusdf['finding_number'] = vdoodf['cve_id']
        nucleusdf['finding_cve'] = vdoodf['cve_id']
        nucleusdf['finding_description'] = vdoodf['description']
        nucleusdf['finding_name'] = vdoodf.apply(lambda row: row.cve_id + ' ' + row.component + ' ' +
                                                                row.component_version, axis=1)
        nucleusdf['finding_path'] = vdoodf.apply(lambda row: row.component + ' ' +
                                                            row.component_version, axis=1)
        nucleusdf['finding_recommendation'] = vdoodf.apply(lambda row: 'Update ' + row.component +
                                                                    ' to a newer version than ' +
                                                                row.component_version, axis=1)
        # anything like # exploits or attacks, impact, vector, cwe, goes here. anything that doesn't map directly
        nucleusdf['finding_references'] = vdoodf.apply(lambda row: 'vdoo.attack_vector:' + str(row.attack_vector) + '\n' +
                                                                'vdoo.impact: ' + str(row.impact) + '\n' +
                                                                'vdoo.number_of_exploits: ' + str(row.number_of_exploits) + '\n' +
                                                                'vdoo.number_of_attacks: ' + str(row.number_of_attacks)
                                                    , axis=1)
        #print(nucleusdf['finding_references'])
        nucleusdf['finding_cvss'] = vdoodf['cvss.cvss_score']
        nucleusdf['finding_severity'] = nucleusdf.apply(lambda row: severity(row.finding_cvss), axis=1)
        nucleusdf['finding_exploitable'] = vdoodf.apply(lambda row: exploits(row.number_of_exploits), axis=1)


        # do these last to prevent NaNs
        nucleusdf['nucleus_import_version'] = "1"
        nucleusdf['scan_type'] = "Application"
        nucleusdf['scan_tool'] = "VDoo"
        nucleusdf['finding_type'] = "Vuln"
        nucleusdf['finding_result'] = "Failed"
        nucleusdf['host_name'] = asset['artifact_name']
        nucleusdf['scan_date'] = image['updated_at']
        nucleusdf['operating_system_version'] = image['distro_version']
        nucleusdf['branch'] = str(i['artifact_id'])

        outputfile = str(i['artifact_id']) + '.csv'
        nucleusdf.to_csv(outputfile, encoding='utf-8')

        post_to_nucleus(i, outputfile)


def post_to_nucleus(i, outputfile):

    # post to nucleus
    with open(outputfile, 'rb') as f:
        # Get the final Nucleus URL to post to
        nucleus_url = str(NUCLEUS_ROOT_URL + '/nucleus/api/projects/' + PROJECT_ID + '/scans')

        print("Posted to URL:", nucleus_url)
        logger.debug("Pushing vuln data to Nucleus for {}".format(i))

        try:
            # Send file with proper header. Keep note of the project ID you need to send
            # file_upload = requests.post(nucleus_url, files={outputfile: f}, headers={'x-apikey': API_KEY},
            #                            proxies=proxies)
            file_upload = requests.post(nucleus_url, files={outputfile: f}, headers={'x-apikey': API_KEY})
            # Print the response from the server
            print(file_upload.content)
            # get status of job and output
            job = json.loads(str(file_upload.text))
            nucleus_url = str(NUCLEUS_ROOT_URL + '/nucleus/api/projects/' + PROJECT_ID + '/jobs/' + str(job['job_id']))
            status = requests.get(nucleus_url, headers={'x-apikey': API_KEY})
            # Print the response from the server
            print(status.content)

        except Exception as e:
            print("Unable to post file to Nucleus. Try checking your Nucleus url and project ID")

            logger.error("Unable to post file to Nucleus for {}. Error: {}".format(i, e))

            print("Error as follows:", e)
        # need error handling for blank scans, we have one of those at the end
    # delete output CSV when done
    os.remove(outputfile)


if __name__ == "__main__":

    # Set up logging
    handler = logging.FileHandler('vdoo-monitoring.log')
    handler.addFilter(HostnameFilter())
    handler.setFormatter(logging.Formatter('%(asctime)s %(hostname)s - %(levelname)s: %(message)s'))

    logger = logging.getLogger()
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)

    images = get_images(headers)
    outputfile = get_image_vulns(images, headers)


