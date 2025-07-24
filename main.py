import ipinfo
import os
import asyncio
import json
import ipaddress
import argparse
import socket
import nmap
import re 
from tabulate import tabulate
from concurrent.futures import ThreadPoolExecutor
from colorama import init, Fore
from termcolor import colored

# Retrieve the Ipinfo access token from environment variables
# How to set environment variable in cmd : setx IPINFO_ACCESS_TOKEN "your_ipinfo_access_token"
access_token = os.getenv('IPINFO_ACCESS_TOKEN')
if not access_token:
    raise ValueError("IPINFO_ACCESS_TOKEN environment variable not set")
handler = ipinfo.getHandler(access_token)


def validate_ip(ip):
    """Validate if the input is a valid IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def lookup_ip_info(ip):
    """Lookup IP information and replace missing data with 'N/A'."""
    details = handler.getDetails(ip)
    return {key: value if value else "N/A" for key, value in details.all.items()}


def lookup_domain_info(domain):
    """Lookup domain information and replace missing data with 'N/A'."""
    details = handler.getDetails(domain)
    return {key: value if value else "N/A" for key, value in details.all.items()}


def print_info_table(info):
    """Print the information in a tabular format with Kali Linux style colors."""
    table = [[colored(key, 'green'), colored(value, 'yellow')] for key, value in info.items()]
    print(tabulate(table, headers=[colored("Field", 'cyan'), colored("Value", 'cyan')], tablefmt="grid"))


def who_is_api():
    """Main function to handle user input and perform lookup."""
    try:
        user_input = input("Enter an IP address or domain: ")

        if validate_ip(user_input):
            info = lookup_ip_info(user_input)
        else:
            info = lookup_domain_info(user_input)

        print_info_table(info)
    except Exception as e:
        print(colored(f"An error occurred: {str(e)}", 'red'))


RED = "\33[91m"
BLUE = "\33[94m"
GREEN = "\033[32m"  # Using the Green Banner
YELLOW = "\033[93m"
PURPLE = '\033[0;35m'
CYAN = "\033[36m"
END = "\033[0m"

# Menu Constants
MENU_PORT_SCANNER = "1"
MENU_TRACEROUTE = "2"
MENU_HTTP_HEADER = "3"
MENU_PING = "4"
MENU_WHOIS_LOOKUP = "5"
MENU_NSLOOKUP = "6"
MENU_SUBNET_CALCULATOR = "7"
MENU_RETURN_MAIN_MENU = "8"
MENU_NETWORK_INFORMATION = "1"
MENU_PROGRAM_INFORMATION = "2"
MENU_EXIT = "3"


# Banner
def program_banner_xray():
    """
  Prints a pre-defined banner in green color.
  """
    banner = f"""
  {GREEN}                              
░░███ ░░███                                
 ░░███ ███   ████████   ██████   █████ ████
  ░░█████   ░░███░░███ ░░░░░███ ░░███ ░███ 
   ███░███   ░███ ░░░   ███████  ░███ ░███ 
  ███ ░░███  ░███      ███░░███  ░███ ░███ 
 █████ █████ █████    ░░████████ ░░███████ 
░░░░░ ░░░░░ ░░░░░      ░░░░░░░░   ░░░░░███ 
                                  ███ ░███ 
                                 ░░██████  
                                  ░░░░░░    
"""

    print(f"{GREEN}{banner}{END}")


def about_me():
    info = [
        [colored("Attribute", 'green', attrs=['bold']), colored("Details", 'green', attrs=['bold'])],
        ["Developer", colored("CyberSeC", 'cyan')],
        ["Location", colored("Unknown", 'cyan')],
        ["Project", colored("Xray - Your Network Toolkit", 'yellow')],
        ["Version", colored("1.1", 'yellow')],
    ]

    print(tabulate(info, tablefmt="fancy_grid"))


# Function to validate the format of an IP address
def validate_ip(ip_address):
    try:
        ipaddress.ip_address(ip_address)  # Convert string to an IP address object
        return True
    except ValueError:  # If conversion fails, the format is invalid
        return False


# Asynchronous function to grab HTTP headers from a given IP address
async def grab_banner_async(ip_address):
    if not validate_ip(ip_address):  # Validate IP address format
        print(colored("Invalid IP address format.", 'red'))
        return

    nm = nmap.PortScanner()  # Create a PortScanner object
    nm.scan(ip_address, '80', arguments='-sS')  # Scan port 80 on the given IP address

    port_state = nm[ip_address]['tcp'][80]['state']  # Get the state of port 80
    if port_state == 'open':  # Check if port 80 is open
        print(colored(f"Port 80 is open on {ip_address}", 'green'))
    else:  # If port 80 is not open, print the state and return
        print(colored(f"Port 80 is {port_state} on {ip_address}", 'red'))
        return

    if port_state == 'open':  # If port 80 is confirmed open
        try:
            reader, writer = await asyncio.open_connection(ip_address,
                                                           80)  # Open a connection to the IP address on port 80
            request = f"HEAD / HTTP/1.1\r\nHost: {ip_address}\r\n\r\n"  # Formulate a HEAD request
            writer.write(request.encode())  # Send the request
            await writer.drain()  # Wait until the request is fully sent
            response = await reader.read(1024)  # Read the response
            headers, _ = response.split(b'\r\n\r\n', 1)  # Split the response to get headers
            headers_dict = {}  # Initialize a dictionary to store headers
            for header in headers.split(b'\r\n'):  # Iterate through each header
                if b': ' in header:  # Check if the header is valid
                    key, value = header.split(b': ', 1)  # Split the header into key and value
                    headers_dict[key.decode()] = value.decode()  # Decode and store the header
            print(json.dumps(headers_dict, indent=2))  # Print the headers in JSON format
        except socket.gaierror:  # Handle network address-related errors
            print(colored("Network address-related error", 'red'))
        except socket.timeout:  # Handle timeout errors
            print(colored("Timeout error", 'red'))
        except Exception as e:  # Handle all other exceptions
            print(colored(f"Error retrieving headers: {str(e)}", 'red'))
        finally:
            writer.close()  # Close the writer
            await writer.wait_closed()  # Wait until the writer is fully closed


# Wrapper function to run the asynchronous grab_banner_async function
def grab_banner():
    asyncio.run(grab_banner_async(ip_address=input(colored("Enter the IP address: ", 'yellow'))))


def nslookup():
    """
    Nslookup to ip or domain address
    :return:
    """
    target_host = input("Enter Target Host: ")
    command = f"nslookup {target_host}"
    output = os.system(command)
    print(output)


def ping():
    target_host = input("Enter Ip address or Domain Name: ")
    command = f"ping {target_host}"
    output = os.system(command)
    print(output)


# Initialize Colorama for colored terminal output
init()


def get_args():
    # Parse command-line arguments for timeout setting
    parser = argparse.ArgumentParser(description='Simple Port Scanner')
    parser.add_argument('--timeout', type=int, default=1, help='Timeout for socket connection in seconds')
    return parser.parse_args()


def scan_port(host, port, description, results, timeout):
    try:
        # Create a socket and attempt to connect to the specified port
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((host, port))
    except socket.timeout:
        # Append result if the port is filtered (timeout)
        results.append([port, description, Fore.YELLOW + 'filtered' + Fore.RESET, ''])
    except ConnectionRefusedError:
        # Append result if the port is closed
        results.append([port, description, Fore.RED + 'closed' + Fore.RESET, ''])
    else:
        # Use nmap to get OS information if the port is open
        nm = nmap.PortScanner()
        os_result = nm.scan(host, arguments='-O')
        if host in os_result['scan'] and 'osmatch' in os_result['scan'][host]:
            os_info = os_result['scan'][host]['osmatch'][0]['name']
        else:
            os_info = 'Not recognized'
        # Append result if the port is open
        results.append([port, description, Fore.GREEN + 'open' + Fore.RESET, os_info])
    finally:
        s.close()


def is_valid_ip(ip):
    # Validate if the input string is a valid IP address
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def is_valid_domain(domain):
    # Validate if the input string is a valid domain name
    regex = re.compile(
        r'^(?:[a-zA-Z0-9]'  # First character of the domain
        r'(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)'  # Sub domain + hostname
        r'+[a-zA-Z]{2,6}$'  # First level TLD
    )
    return re.match(regex, domain) is not None


def port_scanner():
    args = get_args()
    timeout = args.timeout

    while True:
        # Prompt user to enter an IP address or domain
        host_input = input(colored("Enter the IP address or domain: ", 'yellow'))

        if is_valid_ip(host_input) or is_valid_domain(host_input):
            # Ask user for confirmation to scan the entered IP or domain
            validate_scan = input(
                colored(f"Do you want to scan the host {host_input} (y/n): ", 'yellow')).strip().lower()

            if validate_scan in ['y', 'yes']:
                try:
                    # Resolve the host name to an IP address
                    host = socket.gethostbyname(host_input)
                except socket.gaierror:
                    print(f"Can't resolve {host_input}")
                    continue

                # Define common ports to scan
                ports = {
                    20: 'FTP Datatransfer',
                    21: 'FTP Controller Connection',
                    22: 'SSH',
                    23: 'Telnet',
                    25: 'SMTP',
                    53: 'DNS',
                    80: 'HTTP',
                    110: 'POP3',
                    143: 'IMAP',
                    443: 'HTTPS',
                    445: 'Microsoft-DS (Active Directory, Windows shares, Sasser worm, Agobot worm)',
                    1433: 'Microsoft SQL Server',
                    3306: 'MySQL',
                    3389: 'Remote Desktop Protocol (RDP)',
                    8080: 'HTTP-Proxy',
                }
                results = []

                print(f"The Portscan has been started on host {host_input} this can take a while...")

                # Use ThreadPoolExecutor to scan ports concurrently
                with ThreadPoolExecutor(max_workers=20) as executor:
                    futures = [executor.submit(scan_port, host, port, description, results, timeout) for
                               port, description in ports.items()]
                    for future in futures:
                        future.result()

                # Display scan results in a tabular format
                print(f"Scan results for host: {host_input}")
                results.sort(key=lambda x: x[0])
                print(tabulate(results, headers=['Port', 'Description', 'Status', 'OS'], tablefmt='pretty'))
                break
            elif validate_scan in ['n', 'no']:
                print("Please enter a new IP address or domain.")
            else:
                print("Invalid input. Please enter 'y' or 'n'.")
        else:
            print("Invalid IP address or domain. Please enter a valid IP address or domain.")


def subnet_lookup():
    # Prompt the user to input an IP address and subnet mask in CIDR notation (e.g., 192.168.178.1/24)
    ip_subnet = input("Input the Ipaddress and Subnet mask in the CIDR-Notation (example "
                      "192.168.178.1/24): ")

    # Split the input into IP address and subnet mask
    ip, subnet = ip_subnet.split('/')
    subnet = int(subnet)  # Convert subnet mask to integer

    # Convert the IP address into binary representation
    ip_binary = ''.join([bin(int(x) + 256)[3:] for x in ip.split('.')])

    # Calculate the network address by applying the subnet mask and setting the host bits to 0
    network_binary = ip_binary[:subnet] + '0' * (32 - subnet)
    network = '.'.join(str(int(network_binary[i:i + 8], 2)) for i in range(0, 32, 8))

    # Calculate the netmask by converting the subnet length into binary form
    netmask_binary = '1' * subnet + '0' * (32 - subnet)
    netmask = '.'.join(str(int(netmask_binary[i:i + 8], 2)) for i in range(0, 32, 8))

    # Calculate the broadcast address by setting all host bits to 1
    broadcast_binary = ip_binary[:subnet] + '1' * (32 - subnet)
    broadcast = '.'.join(str(int(broadcast_binary[i:i + 8], 2)) for i in range(0, 32, 8))

    # Calculate the wildcard mask by inverting the netmask
    wildcard_mask_binary = '0' * subnet + '1' * (32 - subnet)
    wildcard_mask = '.'.join(str(int(wildcard_mask_binary[i:i + 8], 2)) for i in range(0, 32, 8))

    # Calculate the number of bits for hosts and the maximum number of hosts
    hosts_bits = 32 - subnet
    max_hosts = 2 ** hosts_bits - 2  # Subtract 2 for network and broadcast addresses

    # Calculate the range of valid host addresses
    host_range = f"{network[:-1]}1 - {broadcast[:-1]}{int(broadcast[-1]) - 1}"

    # Print the calculated network details
    print(f"Address       = {ip}")
    print(f"Network       = {network} / {subnet}")
    print(f"Netmask       = {netmask}")
    print(f"Broadcast     = {broadcast}")
    print(f"Wildcard Mask = {wildcard_mask}")
    print(f"Hosts Bits    = {hosts_bits}")
    print(f"Max. Hosts    = {max_hosts}   (2^{hosts_bits} - 2)")
    print(f"Host Range    = {{ {host_range} }}")


def terms_of_service():
    tos_statements = [
        ["1", "This program is intended for educational purposes only. Do not use it for illegal activities."],
        ["2", "You should only perform attacks on devices you own or have permission to test."],
        ["3", "The creator of this program is not responsible for any misuse of information provided by this program."],
        ["4", "The user assumes all responsibility for any actions taken using this program."],
        ["5", "By using this program, you agree to these terms."]
    ]

    tos_table = tabulate(tos_statements, headers=["#", "Terms of Service"], tablefmt="grid")
    print(colored("\n" + tos_table + "\n", 'red'))


def traceroute():
    """
    traceroute to ip or domain address
    :return:
    """
    target_host = input("Target IP address or domain name: ")
    command = f"tracert {target_host}"
    output = (os.system(command))
    print(output)


def menu_net_info():
    menu_options = [
        [colored(MENU_PORT_SCANNER, 'green'), colored("Port Scanner", 'yellow')],
        [colored(MENU_TRACEROUTE, 'green'), colored("Traceroute", 'yellow')],
        [colored(MENU_HTTP_HEADER, 'green'), colored("HTTP Header", 'yellow')],
        [colored(MENU_PING, 'green'), colored("Ping", 'yellow')],
        [colored(MENU_WHOIS_LOOKUP, 'green'), colored("Whois Lookup", 'yellow')],
        [colored(MENU_NSLOOKUP, 'green'), colored("Nslookup", 'yellow')],
        [colored(MENU_SUBNET_CALCULATOR, 'green'), colored("Subnet Calculator", 'yellow')],
        [colored(MENU_RETURN_MAIN_MENU, 'green'), colored("Return to Main Menu", 'yellow')]
    ]

    while True:
        print(colored("\nNetwork Information Menu", 'cyan'))
        print(colored("Please choose an option from the menu below:\n", 'cyan'))
        print(tabulate(menu_options, headers=[colored("Option", 'green'), colored("Description", 'yellow')],
                       tablefmt="grid"))

        option = input(colored("\nEnter your option: ", 'green'))

        try:
            if option == MENU_PORT_SCANNER:
                port_scanner()
            elif option == MENU_TRACEROUTE:
                traceroute()
            elif option == MENU_HTTP_HEADER:
                grab_banner()
            elif option == MENU_PING:
                ping()
            elif option == MENU_WHOIS_LOOKUP:
                who_is_api()
            elif option == MENU_NSLOOKUP:
                nslookup()
            elif option == MENU_SUBNET_CALCULATOR:
                subnet_lookup()
            elif option == MENU_RETURN_MAIN_MENU:
                print(colored("Returning to main menu...", 'yellow'))
                break
            else:
                print(colored("Invalid option. Please select a number between 1 and 8.", 'red'))
        except ValueError:
            print(colored("Invalid input. Please enter the correct format.", 'red'))
        except Exception as e:
            print(colored(f"An error occurred: {str(e)}", 'red'))


def menu_program_info():
    menu_options = [
        [colored("1", 'green'), colored("About Me", 'yellow')],
        [colored("2", 'green'), colored("Terms of Service", 'yellow')],
        [colored("3", 'green'), colored("Return to Main Menu", 'yellow')]
    ]

    while True:
        print(colored("\nProgram Information Menu", 'cyan'))
        print(colored("Version 1.0", 'cyan'))
        print(tabulate(menu_options, headers=[colored("Option", 'green'), colored("Description", 'yellow')],
                       tablefmt="grid"))

        option = input(colored("Enter your option: ", 'green'))

        try:
            if option == "1":
                about_me()
            elif option == "2":
                terms_of_service()
            elif option == "3":
                print(colored("Returning to main menu...", 'yellow'))
                break
            else:
                print(colored("Invalid option. Please select a number between 1 and 3.", 'red'))
        except ValueError:
            print(colored("Invalid input. Please enter the correct format.", 'red'))
        except Exception as e:
            print(colored(f"An error occurred: {str(e)}", 'red'))


def main():
    """
    Main function to run the XRay program with a tabular menu enhanced with Kali Linux style colors.
    """
    program_banner_xray()

    menu_options = [
        [colored(MENU_NETWORK_INFORMATION, 'green'), colored("Network Information", 'yellow')],
        [colored(MENU_PROGRAM_INFORMATION, 'green'), colored("Program Information", 'yellow')],
        [colored(MENU_EXIT, 'green'), colored("EXIT", 'yellow')]
    ]

    while True:
        print(colored("\nWelcome to Xray - Your Network Toolkit", 'cyan'))
        print(colored("Please choose an option from the menu below:\n", 'cyan'))
        print(tabulate(menu_options, headers=[colored("Option", 'green'), colored("Description", 'yellow')],
                       tablefmt="grid"))

        option = input(colored("\nEnter your option: ", 'green'))

        try:
            if option == MENU_NETWORK_INFORMATION:
                menu_net_info()
            elif option == MENU_PROGRAM_INFORMATION:
                menu_program_info()
            elif option == MENU_EXIT:
                print(colored("Exiting Xray... Thank you for using our service.", 'red'))
                break
            else:
                print(colored("Invalid option. Please select a number between 1 and 4.", 'red'))
        except ValueError:
            print(colored("Invalid input. Please enter the correct format.", 'red'))
        except Exception as e:
            print(colored(f"An error occurred: {str(e)}", 'red'))


if __name__ == "__main__":
    main()
