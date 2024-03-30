# DNS Lookup Tools

This repository contains multiple DNS lookup tools for Windows and Linux operating systems.

## Tools List

1. **WindowsDNSCashe**
   - Description: This tool parses the Windows-generated DNS cache (recently looked-up domains) and passes them to abusedb to check for their reputation. All it needs is to first generate the DNS cache by typing in cmd `ipconfig /displaydns > dnscache.txt`, then use the script with the input name `dnscache.txt`, output `output.csv`, and your Abuse API key.

## About

The DNS lookup tools are created by Hossam ElQersh. They provide various tools for performing DNS-related tasks.

## Contributing

Feel free to contribute to this repository by submitting pull requests or opening issues. Your contributions are welcome!

## License

This project is licensed under the [MIT License](LICENSE).
