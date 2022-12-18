import subprocess
import re
import asyncio
import aiohttp
import html
import time

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
            return subprocess.check_output(command.split(" "), stderr=subprocess.DEVNULL).decode("utf-8").split('\n')
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

    async def parse_title_by_url(url):
        try:
            timeout = aiohttp.ClientTimeout(total=3)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0"}, ssl=False) as response:
                    response_text = await response.text()
                    response_text = html.unescape(response_text)
                    return re.search(r"<title>(.*)<\/title>", response_text, re.DOTALL).group(1).replace('\n', ' ')
        except Exception as e:
            print(e)
            return ""


class Domain_dict:

    def __init__(self, domain_name):
        self.__domain_dict = {}
        self.__domain_dict.update({"domain_name": Bash_features.parse_domain_name(domain_name)})
        self.__find_mail_subdomains()
        if flag_find_mail_addresses:
            self.__find_mail_addresses()
    
    def __parse_mx_records(self, line):
        if line == '':
            return None
        try:
            return re.match(r"\d* (.*)\.", line).group(1)
        except AttributeError as e:
            print (f"Cannot parse mail domain in a string: {line}")
            return None

    def __find_second_level_domain(self):
        domain_name = self.__domain_dict["domain_name"]
        try:
            second_level_domain = re.search(r"([\w\-]*\.[\w\-]*)$", domain_name).group(1)
            self.__domain_dict["second_level_domain"] = second_level_domain
        except AttributeError as e:
            print (f"Something weird has happened. Cannot parse 2 level domain from a domain: {domain_name}")
        
    # Find mail subdomains through digging MX records
    def __find_mail_subdomains(self):
        if not "second_level_domain" in self.__domain_dict:
            self.__find_second_level_domain()
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

    def __find_mail_addresses(self):
        if not "second_level_domain" in self.__domain_dict:
            self.__find_second_level_domain()
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

    async def find_open_web_servers(self):
        domain_name = self.__domain_dict["domain_name"]
        web_server_title = await Bash_features.parse_title_by_url(f"https://{domain_name}")
        if web_server_title == "":
            web_server_title = await Bash_features.parse_title_by_url(f"http://{domain_name}")
        if len(web_server_title) > 70:
            web_server_title = web_server_title[0:67] + "..." 
        if web_server_title:
            self.__domain_dict.update({"web_server_title": web_server_title})
                
    def __str__(self):
        domain_name = self.__domain_dict["domain_name"]
        mail_subdomains = self.__domain_dict["mail_subdomains"]
        mail_subdomains_str = "".join([mail_subdomain + " " for mail_subdomain in mail_subdomains])[0:-1]
        web_server_title = ""
        if "web_server_title" in self.__domain_dict:
            web_server_title = self.__domain_dict["web_server_title"].replace(",", ".")
        return f"{domain_name},{mail_subdomains_str},{web_server_title}"
        
async def main():
    #if len(sys.argv) != 2:
    #    print("Usage: python script.py file_name")
    #    exit()

    domains = []
    file_name = "/tmp/1412.txt"
    #file_name = sys.argv[1]
    try:
        with open(file_name) as f:
            for line in f:
                domains.append(line)
    except Exception as e:
        print(f"No such file: \"{file_name}\". Try again!")
        exit()
    app_tasks = [asyncio.create_task(task(line)) for line in domains]
    await asyncio.gather(*app_tasks)


async def task(line):
    start = time.monotonic()
    domain_name = Bash_features.parse_domain_name(line)
    if domain_name:
        x = Domain_dict(domain_name)
        await x.find_open_web_servers()
        print(x)
    print(time.monotonic() - start)

if __name__ == "__main__":
    asyncio.run(main())