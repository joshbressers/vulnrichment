#!/usr/bin/env python

from glob import glob
import json
import re

cve_data_files = glob("**/**/CVE-*.json")
regex = r"""<xsd:pattern value="cpe:2\.3:[aho\*\-](:(((\?*|\*?)([a-zA-Z0-9\-\._]|(\\[\\\*\?!"#$$%&'\(\)\+,/:;<=>@\[\]\^`\{\|}~]))+(\?*|\*?))|[\*\-])){5}(:(([a-zA-Z]{2,3}(-([a-zA-Z]{2}|[0-9]{3}))?)|[\*\-]))(:(((\?*|\*?)([a-zA-Z0-9\-\._]|(\\[\\\*\?!"#$$%&'\(\)\+,/:;<=>@\[\]\^`\{\|}~]))+(\?*|\*?))|[\*\-])){4}"/>"""

#with open("regex.txt") as f:
#    regex = f.readlines()[0].rstrip()

matcher = re.compile(regex) 


for cve_file in cve_data_files:
    with open(cve_file, "r") as f:
        cve_data = json.load(f)

        for i in cve_data["containers"]["adp"]:
            if "affected" in i:
                for j in i["affected"]:
                    if "cpes" in j:
                        for c in j["cpes"]:
                            if not matcher.match(c):
                                print(f"BAD {cve_data["cveMetadata"]["cveId"]} {c}")
                            else:
                                print(f"GOOD {cve_data["cveMetadata"]["cveId"]} {c}")
