import re
import asyncio
import aiohttp
import html
import time
import sys

flag_find_mail_addresses = False
start = time.monotonic()
sem = asyncio.Semaphore(10)
ans = []

class Bash_features:
    def parse_domain_name(line):
        if line == '':
            return None
        try:
            return re.match(r"(?:.*:\/\/){0,1}([\w\-\.]*)", line).group(1)
        except AttributeError as e:
            print (f"Cannot parse domain in a string: {line}")
            return None

    async def execute_bash(command):
        try:
            async with sem:
                proc = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE)
                stdout, stderr = await proc.communicate()
                return stdout.decode("utf-8").split('\n')
        except Exception as e:
            print(f"Bash command error ({command}): {e}\n stderr: {stderr}")
            return None

    async def check_open_ports_nmap(ip, ports):
        nmap_search_string = "nmap -Pn -R -p" + "".join([str(port) + "," for port in ports]) + f" {ip} -oG -"
        nmap_output = await Bash_features.execute_bash(nmap_search_string)
        #Determine answer line and parse open ports
        open_ports = []
        for line in nmap_output:
            if re.search("open", line):
                open_ports = re.findall(r"(\d*)\/open", line)
                open_ports = list(map(int, open_ports))
        return open_ports

    # Find IP addresses through digging host
    async def find_ip_addresses(domain_name):
        ip_addresses = await Bash_features.execute_bash(f"dig +short {domain_name}")
        ip_addresses = [ip for ip in ip_addresses if ip]
        return ip_addresses

    async def parse_title_by_url(url):
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0"}
                async with session.get(url, headers=headers, ssl=False) as response:
                    response_text = await response.text()
                    response_text = html.unescape(response_text)
                    result = re.search(r"<title>(.*)<\/title>", response_text, re.DOTALL).group(1).replace('\n', ' ')
                    return result
        except Exception as e:
            #print(e)
            return ""


class Domain_dict:

    def __init__(self, domain_name):
        self.__domain_dict = {}
        self.__domain_dict.update({"domain_name": Bash_features.parse_domain_name(domain_name)})
    
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
    async def find_mail_subdomains(self):
        if not "second_level_domain" in self.__domain_dict:
            self.__find_second_level_domain()
        second_level_domain = self.__domain_dict["second_level_domain"]
        dig_short_mx_answer = await Bash_features.execute_bash(f"dig +short mx {second_level_domain}")
        mail_subdomains = []
        for line in dig_short_mx_answer:
            mail_subdomain = self.__parse_mx_records(line)
            ip_addresses = await Bash_features.find_ip_addresses(mail_subdomain)
            if (mail_subdomain) and (ip_addresses != []):
                mail_subdomains.append(mail_subdomain)
        
        # Delete all duplicates
        mail_subdomains = [*set(mail_subdomains)]
        self.__domain_dict.update({"mail_subdomains": mail_subdomains})

    async def __find_mail_addresses(self):
        if not "second_level_domain" in self.__domain_dict:
            self.__find_second_level_domain()
        second_level_domain = self.__domain_dict["second_level_domain"]
        emailharvester_answer = await Bash_features.execute_bash(f"emailharvester -d {second_level_domain}")
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

    async def find_ip_addresses(self):
        domain_name = self.__domain_dict["domain_name"]
        ip_addresses = await Bash_features.find_ip_addresses(domain_name)
        if ip_addresses != []:
            self.__domain_dict.update({"ip_addresses": ip_addresses})
    
                
    def __str__(self):
        domain_name = self.__domain_dict["domain_name"]
        mail_subdomains = self.__domain_dict["mail_subdomains"]
        mail_subdomains_str = "".join([mail_subdomain + " " for mail_subdomain in mail_subdomains])[0:-1]
        web_server_title = ""
        ip_addresses = self.__domain_dict.get("ip_addresses", "")
        ip_addresses_str = "".join([ip_address + " " for ip_address in ip_addresses])[0:-1]
        web_server_title = self.__domain_dict.get("web_server_title", "").replace(",", ".")
        return f"{domain_name},{mail_subdomains_str},{ip_addresses_str},{web_server_title}"


async def main():
    if len(sys.argv) != 2 and len(sys.argv) != 3:
        print("Usage: python script.py <input_file> <output_file>")
        exit()

    domains = []
    input_file_name = sys.argv[1]
    output_file_name = sys.argv[2]

    try:
        with open(input_file_name) as f:
            for line in f:
                domains.append(line)
    except Exception as e:
        print(f"No such file: \"{input_file_name}\". Try again!")
        exit()
    
    try:
        with open(output_file_name, "w") as f:
                f.write('test')
    except:
        print(f"Cannot print to: \"{output_file_name}\". Try again!")
        exit()

    app_tasks = [asyncio.create_task(task(line)) for line in domains]
    wait_tasks = await asyncio.wait(app_tasks)

    ans.sort()
    try:
        with open(output_file_name, "w+") as f:
            for line in ans:
                f.write(line + '\n')
    except:
        print(f"Cannot print to: \"{output_file_name}\". Try again!")
        exit()
    print(f"Task finshed. Total time: {time.monotonic() - start}")


async def task(line):
    line = line.replace('\n','')
    domain_name = Bash_features.parse_domain_name(line)
    if domain_name:
        domain_dict = Domain_dict(domain_name)
        await domain_dict.find_open_web_servers()
        await domain_dict.find_mail_subdomains()
        await domain_dict.find_ip_addresses()
        if flag_find_mail_addresses:
            await domain_dict.find_mail_addresses()
        ans.append(str(domain_dict))
        print(domain_dict)

if __name__ == "__main__":
    asyncio.run(main())