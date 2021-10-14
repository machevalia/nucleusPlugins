#!/usr/bin/python3.7
__author__ = "Nucleus  Security"
__license__ = "Apache Free License"
__version__ = "0.1"
# 27 Sep 2021

import pandas as pd
import gc
import sys
import argparse

def customParser(inputPath, outputPath):
    try:
        df = pd.read_excel(inputPath, engine='openpyxl')
    except Exception as e:
        print('Input file must be in XLSX format.')
        print("Error: ", e)
        exit(1)

    # clean up NaN values
    df = df.fillna('')

    #print(df)

    # check for missing columns and handle the error if we find any
    if not {'AssetName', 'IPAddress', 'IPLocation', 'OS', 'Mac', 'IT Group Owner', 'Business Department',
            'System Description', 'Maintenance window', 'Maintenance schedule', 'Support information',
            'Security risk', 'Data sensitivity'}.issubset(df.columns):
        print('One or more expected columns is missing from the input file.')
        print('Expected columns in any order: ')
        print("AssetName, IPAddress, IPLocation, OS, Mac, IT Group Owner, Business Department, System Description, Maintenance window, Maintenance schedule, Support information, Security risk, Data sensitivity")
        exit(1)

    # deal with spaces
    df.rename(columns={'IT Group Owner': 'owner',
                       'Business Department': 'department',
                       'System Description': 'description',
                       'Maintenance window': 'window',
                       'Maintenance schedule': 'schedule',
                       'Support information': 'support',
                       'Security risk': 'risk',
                       'Data sensitivity': 'sensitivity'}, inplace=True)

	
    df['asset_criticality'] = df['Importance']
    df['data_sensitivity'] = df['sensitivity']
					   
    # remap/clean up criticality
    df['asset_criticality'] = df['asset_criticality'].str.replace('critical', 'Critical')
    df['asset_criticality'] = df['asset_criticality'].str.replace('high', 'High')
    df['asset_criticality'] = df['asset_criticality'].str.replace(' standard', 'Moderate')
    df['asset_criticality'] = df['asset_criticality'].str.replace('standard', 'Moderate')
    #df['asset_criticality'] = df['asset_criticality'].str.replace('', 'Moderate')
    df['asset_criticality'] = df['asset_criticality'].str.replace('low', 'Low')


    # build asset_info (custom metadata) column.
    df['asset_info'] = df.apply(lambda row: 'lansweeper.domain:' + str(row.Domain) + ';' +
                                            'lansweeper.description:' + str(row.Description) + ';' +
                                            'lansweeper.manufacturer:' + str(row.Manufacturer) + ';' +
                                            'lansweeper.model:' + str(row.Model) + ';' +
                                            'lansweeper.location:' + str(row.Location) + ';' +
                                            'lansweeper.iplocation:' + str(row.IPLocation) + ';' +
                                            'lansweeper.it_group_owner:' + str(row.owner) + ';' +
                                            'lansweeper.business_department:' + str(row.department) + ';' +
                                            'lansweeper.system_description:' + str(row.description) + ';' +
                                            'lansweeper.documentation:' + str(row.Documentation) + ';' +
                                            'lansweeper.maintenance_window:' + str(row.window) + ';' +
                                            'lansweeper.maintenance_schedule:' + str(row.schedule) + ';' +
                                            'lansweeper.importance:' + str(row.Importance) + ';' +
                                            'lansweeper.support_information:' + str(row.support) + ';' +
                                            'lansweeper.security_risk:' + str(row.risk) + ';' +
                                            'lansweeper.asset_criticality:' + str(row.asset_criticality) + ';' +
                                            'lansweeper.data_sensitivity:' + str(row.sensitivity) + ';' +
                                            'lansweeper.assettype:' + str(row.AssetType) + ';' +
                                            'lansweeper.type:' + str(row.Type)
                                , axis=1)

    # map the remaining lansweeper column names to Nucleus. lansweeper name on left. nucleus name on right
    df.rename(columns={'AssetName': 'host_name',
                       'IPAddress': 'ip_address',
                       'IPLocation': 'asset_location',
                       'OS': 'operating_system_name',
                       'Mac': 'mac_address'}, inplace=True)

    # add the columns that weren't there
    df['nucleus_import_version'] = '1'
    df['scan_type'] = 'Host'
    df['scan_tool'] = 'Asset'

    # reorder the columns, drop the columns we don't need (anything not in this list gets dropped)
    df = df[['nucleus_import_version', 'scan_type', 'scan_tool', 'host_name', 'ip_address', 'asset_location',
             'operating_system_name', 'mac_address', 'asset_info']]

    # write the CSV
    try:
        df.to_csv(outputPath, index=False)
    except:
        print("Error writing file (make sure destination file doesn't already exist.")
        exit(1)


# Make this script able to handle inputfile and outputfile selections
def get_args():
    parser = argparse.ArgumentParser(description="For parsing lansweeper XLSX files to be uploaded into Nucleus")

    # List arguments. Should only include input file and output file
    parser.add_argument('-i', dest='inputFile', help="Path to lansweeper XLSX file to parse", required=True)
    parser.add_argument('-o', dest='outputFile', help="Path to CSV file output", required=True)

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
