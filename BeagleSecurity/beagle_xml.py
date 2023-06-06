#!/usr/bin/python3
__author__ = "Assura, Inc."
__license__ = "MIT License"
__version__ = "1.0"
import sys
import xml.etree.ElementTree as ET

# Read the input XML file from the command line argument
input_file = sys.argv[1]

# Read the XML data from the file
with open(input_file, "r") as f:
    xml_data = f.read()

# Replace spaces in specific tags
xml_data = xml_data.replace('<Third party>', '<Third_party>').replace('</Third party>', '</Third_party>')
xml_data = xml_data.replace('<Findings description>', '<Findings_description>').replace('</Findings description>', '</Findings_description>')

# Parse the modified XML data
tree = ET.ElementTree(ET.fromstring(xml_data))

# Create the root element for the output XML
root = ET.Element("nucleusCustomScan")

# Add child elements to the root
import_version = ET.SubElement(root, "nucleus_import_version")
import_version.text = "1"

scan_tool = ET.SubElement(root, "scan_tool")
scan_tool.text = "Beagle"

scan_type = ET.SubElement(root, "scan_type")
scan_type.text = "Application"

assets = ET.SubElement(root, "assets")
asset = ET.SubElement(assets, "asset")

# Extract the report generated date from Beagle XML and populate the scan_date field in Nucleus
report_generated_date = tree.getroot().attrib.get("generated")
if report_generated_date is not None:
    scan_date = ET.SubElement(root, "scan_date")
    scan_date.text = report_generated_date

# Extract data from the input XML and populate the output XML
application = tree.find("application")
if application is not None:
    host_name = application.attrib.get("name")
    host_name_element = ET.SubElement(asset, "host_name")
    host_name_element.text = host_name

    findings = ET.SubElement(asset, "findings")

    vulnerabilities = tree.find("vulnerabilities")
    if vulnerabilities is not None:
        for vulnerability in vulnerabilities.iter("vulnerability"):
            finding = ET.SubElement(findings, "finding")

            finding_type = ET.SubElement(finding, "finding_type")
            finding_type.text = "Vuln"

            finding_number = ET.SubElement(finding, "finding_number")
            finding_number.text = vulnerability.attrib.get("title")

            finding_name = ET.SubElement(finding, "finding_name")
            finding_name.text = vulnerability.attrib.get("title")

            finding_severity = ET.SubElement(finding, "finding_severity")
            finding_severity.text = vulnerability.attrib.get("impact")

            finding_description = vulnerability.find("description").text.strip() if vulnerability.find("description") is not None else vulnerability.find("Findings_description").text.strip()
            finding_description_element = ET.SubElement(finding, "finding_description")
            finding_description_element.text = "<![CDATA[{}]]>".format(finding_description)

            recommendation = vulnerability.find("recommendation")
            if recommendation is not None:
                finding_recommendation_element = ET.SubElement(finding, "finding_recommendation")
                finding_recommendation_element.text = "<![CDATA[{}]]>".format(recommendation.text.strip())

            occurrences = vulnerability.findall("occurrences")
            if occurrences:
                finding_output_element = ET.SubElement(finding, "finding_output")
                users = []
                for occurrence in occurrences:
                    for child in occurrence:
                        if child.tag != "status":
                            users.append(child.text)
                finding_output_element.text = ", ".join(users)

# Create the output XML tree
output_tree = ET.ElementTree(root)

# Remove XML header and format output
output_bytes = ET.tostring(root, encoding="UTF-8", method="xml")
output_string = output_bytes.decode("utf-8").replace('<?xml version="1.0" encoding="UTF-8"?>', '')
formatted_output = output_string.strip()

# Replace escaped HTML entities with original symbols
formatted_output = formatted_output.replace("&lt;", "<").replace("&gt;", ">")

# Write the output XML to a file specified in the command line argument
output_file = sys.argv[2]
with open(output_file, "w") as f:
    f.write(formatted_output)
