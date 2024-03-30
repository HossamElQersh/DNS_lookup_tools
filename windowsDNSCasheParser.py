import re
import csv
import requests
import argparse
import pyfiglet




def parse_args():
    parser = argparse.ArgumentParser(description="Process DNS records and check for abuse using AbuseIPDB.\nCreated "                                          "by ElQersh")
    parser.add_argument("-i", "--input", help="Input file windows format DNS cashe to generate it write in cmd 'ipconfig/displaydns > dnscache.txt' ")
    parser.add_argument("-o", "--output", help="Output file to save results (CSV format)")
    parser.add_argument("-k", "--api_key", help="API key for AbuseIPDB")
    args = parser.parse_args()

    if not any(vars(args).values()):
        figlet = pyfiglet.Figlet()
        ascii_art = figlet.renderText("DNS Cashe parser!\n")
        print(ascii_art)
        parser.print_help()
        parser.exit()

    if not args.input:
        parser.error("Input file is missing. Please provide an input file using the -i or --input option.")
    if not args.output:
        parser.error("Output file is missing. Please provide an output file using the -o or --output option.")
    if not args.api_key:
        parser.error("API key is missing. Please provide an API key using the -k or --api_key option.")

    return args


def read_dns_records(input_file):
    dns_records = []
    dnsRecord_temp = {
        "Record Name": None,
        "Record Type": None,
        "TTL": None,
        "Data length": None,
        "Section": None,
        "IP Address": None
    }
    keys = ["Record Name", "Record Type", "TTL", "Data length", "Section", "IP Address"]
    dnsRecord = dnsRecord_temp.copy()
    with open(input_file, 'r') as file:
        for line in file:
            if "----------------------------------------" in line:
                line = file.readline()
                if "No" not in line:
                    for i in range(0, 6):
                        split_string = line.split(':',1)
                        value = keys[i]
                        dnsRecord[value] = split_string[1].strip()
                        line = file.readline()
                if None not in dnsRecord.values():
                    dns_records.append(dnsRecord)
                    dnsRecord = dnsRecord_temp.copy()
    return dns_records

def check_abuseipdb(ip_address, api_key):
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90,
        "verbose": "",
    }
    headers = {
        "Key": api_key,
        "Accept": "application/json",
    }
    response = requests.get(url, params=params, headers=headers)
    if response.status_code == 200:
        abuseResponse = response.json()
        return abuseResponse
    else:
        print(f"Failed to check AbuseIPDB for IP address {ip_address}. Status code: {response.status_code}")
        return None

def main():
    args = parse_args()
    api_key = args.api_key
    input_file = args.input
    output_file = args.output

    dns_records = read_dns_records(input_file)

    for record in dns_records:
        ip_address = record["IP Address"]
        result = check_abuseipdb(ip_address, api_key)
        if result:
            record["AbuseDB"] = result["data"]["abuseConfidenceScore"]

    fieldnames = ["Record Name", "Record Type", "TTL", "Data length", "Section", "IP Address","AbuseDB"]
    with open(output_file, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        for record in dns_records:
            writer.writerow(record)

    print(f"CSV file '{output_file}' has been created successfully.")

if __name__ == "__main__":
    main()
