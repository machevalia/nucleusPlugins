This script is a command line tool for easily converting Dome9 csv output into a Nucleus format for easy upload. The script iterates through the Dome9 file, normalizing it into the Nucleus Custom Schema and then writes it to CSV output. The script can also optionally POST the file to your designated Nucleus project.

Install:

This project uses Conda to manage the Python virtual environment.

Conda can be [downloaded here](https://docs.conda.io/projects/conda/en/latest/user-guide/install/download.html)

The documentation for managing the environment [can be found here](https://conda.io/projects/conda/en/latest/user-guide/tasks/manage-environments.html)

The process for creating the environment is:
1. `conda env create -f environment.yml`  with the environment.yml reference to the environment yaml in the project.
2. `conda activate nucleus-plugin` to activate your virtual environment
3. To deactivate the environment, execute `conda deactivate`

Usage:
- -i for the input Dome9 file path
- -o for the output file path for the output csv

**Example:** `python3 dome9_2nucleus_csv.py -i files/dome9_findings.csv -o dome9_2nucleus.csv -# 11000176`

Optional: 
- - -# Project ID of the Nucleus project to which you to POST the output file

**Note**: If you want to post the file to Nucleus you will need to get an API key from the Nucleus console and update the NUCLEUS_ROOT_URL in the python script.