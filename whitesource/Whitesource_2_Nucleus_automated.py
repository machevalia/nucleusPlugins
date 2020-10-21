#!/usr/bin/python3

####### Script to download reports (JSON) from whitesource SAAS, transform them (CSV) and upload them to Nucleus SAAS ############

import json
import csv

# Used to post the whitesource file to Nucleus
import requests
import time
import datetime
from pathlib import Path

# Enter in the root URL of your Nucleus instance.
NUCLEUS_ROOT_URL = "https://XXXXXXXX.nucleussec.com"

# retrieve this API_KEY from Nucleus GUI. Must be Admin.
NUCLEUS_API_KEY = ""

#project ID from the APPSEC project in Nucleus
NUCLEUS_PROJECT_ID = ""

#retrieve this API_KEY (of the nucleus service user) in whitesource. Must have whitesource admin user.
WHITESOURCE_USER_KEY = ""


# Product tokens in whitesource
WHITESOURCE_PRODUCT_TOKENS="""
{
    "Product name 1":"",
    "Product name 2":""
}
""" 

def post_to_nucleus(outputfile):

    with open(outputfile, 'rb') as f:
        nucleus_url = str(NUCLEUS_ROOT_URL +
                          '/nucleus/api/projects/'+NUCLEUS_PROJECT_ID+'/scans')
        print("Posted to URL:", nucleus_url)
        file_upload = requests.post(
            nucleus_url, files={outputfile: f}, headers={'x-apikey': NUCLEUS_API_KEY})
        print(file_upload.content)


def get_from_whitesource(productToken):     
    json = {
	    "requestType" : "getProductVulnerabilityReport",
	    "userKey": WHITESOURCE_USER_API_KEY,
	    "productToken" : productToken,
	    "format" : "json"
    }
    # For debug
    #print(json)
    response=requests.post('https://app.whitesourcesoftware.com/api/v1.3', json=json)

    # For debug
    print(response.content)
    return response.content

#need to convert JSON report from whitesource to CSV for Nucleus :/ 
def customParser(inputJsonString, outputPath):
 
    jsonObj = json.loads(inputJsonString)

    # For debug
    # text_file=open(outputPath+".json","wb")
    # text_file.write(inputJsonString)
    # text_file.close()
     
    with open(outputPath, 'w', newline='') as csvfile:	
        csvwriter = csv.writer(csvfile, delimiter=',')
        csvwriter.writerow(['nucleus_import_version', 'host_name', 'scan_type', 'scan_tool', 'finding_type', 'finding_cve', 'finding_number','finding_name', 'finding_severity', 'finding_description', 'finding_solution', 'finding_output', 'finding_path', 'finding_result'])
        try:
            for vulnerability in jsonObj["vulnerabilities"]:
                csv_line = []
                host_name = vulnerability["product"] + ": " + vulnerability["project"]
                vulnName = vulnerability["name"]
                severity = vulnerability["severity"]
                vulnDescription = vulnerability["description"]
                library = vulnerability["library"]["name"]

                if "topFix" not in vulnerability:
                    solutionDescription=""
                else:
                    solutionDescription = vulnerability["topFix"]["fixResolution"]

                if "library" not in vulnerability:
                    finding_output = library
                else:
                    finding_output = json.dumps(vulnerability["library"])

                finding_path=vulnerability["library"]["filename"]

                csv_line = ['1', host_name, "Application", "WhiteSource", "Vuln", vulnName, vulnName+host_name,vulnName+": "+library, severity, vulnDescription, solutionDescription, finding_output, finding_path, 'FAILED']
				
                if csv_line != []:
                    csvwriter.writerow(csv_line)
                else:
                    pass
		
            return csvfile
        except Exception as e:
            print("Error, probably bad json document. Check that you are trying to parse the correct doc type")
            print("Error was the following:"+ str(e))
            error_file=open("error.log","a")
            error_file.write(str(datetime.datetime.now()) + " Error was the following:"+ str(e)+"\n")
            error_file.close()


if __name__ == "__main__":
    #get all reports
    jsonProductsToken = json.loads(WHITESOURCE_PRODUCT_TOKENS)

    #loop over all reports (=whitesource project)
    for product in jsonProductsToken:
        inputJsonFile = get_from_whitesource(jsonProductsToken[product])
        time.sleep(5)
        #this path works only on linux. 
        outputPath=str(Path.home())+"/"+product+".csv"
        outputfile = customParser(inputJsonFile, outputPath)
        post_to_nucleus(outputPath)
