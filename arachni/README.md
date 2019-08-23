Install:

Need to install python3 and the requests library


Usage:

CLI tool

python arachni_json_parse.py -i <arachni json input file> -o <nucleus json outputfile>

Optional: -# <Project ID of the Nucleus project to which you want to upload the outputfile>

If a project ID is not specified, the script will just create a json file in the local directory. If a project ID is specified, then will post the Nucleus outputfile to that Nucleus project.

Note: If you want to post the file to Nucleus you will need to get an API key from the Nucleus console and update the NUCLEUS_ROOT_URL in the python script.