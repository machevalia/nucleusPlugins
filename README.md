# NucleusPlugins
This repo is for the community to contribute any custom parsers for scan tools which Nucleus does not yet support. We know that keeping up with all the new scanning tools out there is a collaborative process, and want to support as many tools as possible. 
 

An example parser has been uploaded into the Whitesource folder to parse Whitesource xml output into a Nucleus csv format. Feel free to use this template as a future parsing script, or feel free to completely chop it up.

For examples of custom csv, xml, or json files that Nucleus supports, refer to the Nucleus docs at https://help.nucleussec.com/docs/custom-scans.

You will get credit for your parsers that you upload. If you have created a custom parser for Nucleus, please submit a pull request! We will reach out to you with any questions we have/tests etc. 


## Instructions for use:
1. Install python 3.6 or higher
2. Open the command line
3. Install python requests library `pip install requests` (note you may need to upgrade pip if you just installed python)
4. Find the output file you would like to convert to Nucleus format and copy it to somewhere you can easily access it
5. Navigate in the cli to one of the directories where the plugins are located
6. **OPTIONAL**: If you want to automatically POST the output file to your Nucleus account, you will need to update 2 variables at the top of the python script

* NUCLEUS_ROOT_URL = the root url (without trailing slash) to your Nucleus instance (ie which url do you go to log into the Nucleus UI)

* API_KEY = The API key you generate in the Nucleus UI to be able to programmatically access your Nucleus account. NOTE: you can also create an API-only account and use this api key
7. Run the script using standard python cli commands

## Standard flags for Nucleus plugins:

-i --inputfile   This is the relative or absolute path to the file you wish to convert. Include the file format (eg ../../files/nucleus/crowdstrike_output.csv). **REQUIRED**

-o --outputfile  This is the relative or absolute path to the file which will be outputted from the script (eg ../../files/nucleus/crowdstrike_converted_to_nucleus_format.csv) **REQUIRED**

-# --project_id  This is the id of the Nucleus project you are going to upload the output file to. When this flag is set, the script will automatically try to POST the output file to Nucleus. You can find this on the "Global Dashboard" page in the Nucleus UI. **OPTIONAL**

## Unique Flags:

Some plugins have unique flags depending on their output. You can find these by just running the command `python <parser_name.py>` where parser_name is the name of the plugin you want to run. 