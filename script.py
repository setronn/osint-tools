import subprocess
import re
import requests
import html
import sys

flag_find_mail_addresses = False

class Bash_features:
    def parse_domain_name(line):
        if line == '':
            return None
        try:
            return re.match(r"(?:.*:\/\/){0,1}([\w\-\.]*)", line).group(1)
        except AttributeError as e:
            print (f"Cannot parse domain in a string: {line}")
            return None

    def execute_bash(command):
        try:
            return subprocess.check_output(command.split(" ")).decode("utf-8").split('\n')
        except subprocess.CalledProcessError as e:
            print(f"Bash command error ({command}): {e.output}")
            return None

    def check_open_ports_nmap(ip, ports):
        nmap_search_string = "nmap -Pn -R -p" + "".join([str(port) + "," for port in ports]) + f" {ip} -oG -"
        nmap_output = Bash_features.execute_bash(nmap_search_string)
        #Determine answer line and parse open ports
        open_ports = []
        for line in nmap_output:
            if re.search("open", line):
                open_ports = re.findall(r"(\d*)\/open", line)
                open_ports = list(map(int, open_ports))
        return open_ports

    # Find IP addresses through digging host
    def find_ip_addresses(domain_name):
        ip_addresses = Bash_features.execute_bash(f"dig +short {domain_name}")
        ip_addresses = [ip for ip in ip_addresses if ip]
        return ip_addresses

    def parse_title_by_url(url):
        html_encoded_response = requests.get(url, verify=False).text
        response = html.unescape(html_encoded_response)
        try:
            return re.search(r"<title>(.*)<\/title>", response, re.DOTALL).group(1)
        except AttributeError as e:
            print (f"Cannot find <title> in: {url}.")
            return None


class Domain_dict:

    __domain_dict = {}
    requests.packages.urllib3.disable_warnings()

    # There is should be a valid domain
    def __init__(self, domain_name):
        self.__domain_dict.update({"domain_name": Bash_features.parse_domain_name(domain_name)})
        self.find_mail_subdomains()
        self.find_open_web_servers()
        if flag_find_mail_addresses:
            self.find_mail_addresses()
    
    def __parse_mx_records(self, line):
        if line == '':
            return None
        try:
            return re.match(r"\d* (.*)\.", line).group(1)
        except AttributeError as e:
            print (f"Cannot parse mail domain in a string: {line}")
            return None

    def find_second_level_domain(self):
        domain_name = self.__domain_dict["domain_name"]
        try:
            second_level_domain = re.search(r"([\w\-]*\.[\w\-]*)$", domain_name).group(1)
            self.__domain_dict["second_level_domain"] = second_level_domain
        except AttributeError as e:
            print (f"Something weird has happened. Cannot parse 2 level domain from a domain: {domain_name}")
        
    # Find mail subdomains through digging MX records
    def find_mail_subdomains(self):
        if not "second_level_domain" in self.__domain_dict:
            self.find_second_level_domain()
        second_level_domain = self.__domain_dict["second_level_domain"]
        dig_short_mx_answer = Bash_features.execute_bash(f"dig +short mx {second_level_domain}")
        mail_subdomains = []
        for line in dig_short_mx_answer:
            mail_subdomain = self.__parse_mx_records(line)
            if (mail_subdomain) and (Bash_features.find_ip_addresses(mail_subdomain) != []):
                mail_subdomains.append(mail_subdomain)
        
        # Delete all duplicates
        mail_subdomains = [*set(mail_subdomains)]
        self.__domain_dict.update({"mail_subdomains": mail_subdomains})

    def find_mail_addresses(self):
        if not "second_level_domain" in self.__domain_dict:
            self.find_second_level_domain()
        second_level_domain = self.__domain_dict["second_level_domain"]
        emailharvester_answer = Bash_features.execute_bash(f"emailharvester -d {second_level_domain}")
        # Locate string "[+] Emails found:" and parse emails from next strings
        mail_addresses = []
        flag = 0
        for line in emailharvester_answer:
            if flag == 1:
                if line:
                    mail_addresses.append(line)
            elif "[+] Emails found:" in line:
                flag = 1
        self.__domain_dict.update({"mail_addresses": mail_addresses})

    def find_open_web_servers(self):
        domain_name = self.__domain_dict["domain_name"]
        open_ports = Bash_features.check_open_ports_nmap(domain_name, [80,443])
        web_server_url = ""
        if 443 in open_ports:
            web_server_url = f"https://{domain_name}"
        elif 80 in open_ports:
            web_server_url = f"http://{domain_name}"
        else:
            return
        web_server_title = Bash_features.parse_title_by_url(web_server_url)
        if len(web_server_title) > 70:
            web_server_title = web_server_title[0:47] + "..." 
        if web_server_title:
            self.__domain_dict.update({"web_server_url": web_server_url, "web_server_title": web_server_title})
                
    def __str__(self):
        domain_name = self.__domain_dict["domain_name"]
        mail_subdomains = self.__domain_dict["mail_subdomains"]
        mail_subdomains_str = "".join([mail_subdomain + " " for mail_subdomain in mail_subdomains])[0:-1]
        web_server_url = ""
        web_server_title = ""
        if "web_server_url" in self.__domain_dict:
            web_server_url = self.__domain_dict["web_server_url"]
            web_server_title = self.__domain_dict["web_server_title"].replace(",", ".")
        return f"{domain_name},{mail_subdomains_str},{web_server_url},{web_server_title}"
            

#class Domain_dict_array:
#    __domain_dict_array = []
#
#    def __init__(self, file_name):
#        with open(file_name) as f:
#            for line in f:
#                domain_name = Bash_features.parse_domain_name(line)
#                if domain_name:
#                    x = Domain_dict(domain_name)
#                    self.__domain_dict_array.append(x)
#    
#    def __str__(self):
#        for domain_dict in self.__domain_dict_array:
#            print(domain_dict)
#        return "".join(str(domain_name_output) + "\n" for domain_name_output in self.__domain_dict_array)
        

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py file_name")
        exit()
    
    file_name = sys.argv[1]
    try:
        with open(file_name) as f:
            for line in f:
                domain_name = Bash_features.parse_domain_name(line)
                if domain_name:
                    print(Domain_dict(domain_name))
    except Exception as e:
        print(f"No such file: \"{file_name}\". Try again!")
        exit()