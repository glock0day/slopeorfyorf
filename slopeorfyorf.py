import requests
import socket
import re
import ssl
import whois
import json
import urllib.parse
from ipwhois import IPWhois
import sys
import time

banner = """
====================================
   SLOPEORFYORF FRAMEWORK 
   DEV: GLOCK_0DAY
====================================
"""

options = {"url": None, "module": None}

def help_menu():
    print("""
Komutlar:
    show modules          => Modülleri göster
    use <module>          => Modül seç
    set url <hedef>       => Hedef URL belirle
    show options          => Seçilen seçenekleri göster
    run                   => Modülü çalıştır
    back                  => Modülden çık
    help                  => Yardım menüsü
    exit                  => Çıkış
""")

module_list = [
    "sqli","xss","portscan","dirscan","subfinder","headerscan","sslcheck","corscheck",
    "openredirect","robots_scan","sensitivefiles","httplogger","payloadtester","cvechecker",
    "pysh","linkvalidator","whoislookup","geolocate","reversedns","asnlookup",
    "autoreporter","liveurl","jwtinspect","cspevaluator","emailharvest","sitecrawler"
]

def show_modules():
    print("Mevcut Modüller:")
    for m in module_list:
        print(f"  {m}")

def show_options():
    print(f"URL    : {options['url']}\nMODULE : {options['module']}")

# ---------------- Tarama Fonksiyonları ---------------- #
def sqli_scanner(url):
    payload = "' OR '1'='1"
    try:
        r = requests.get(url + payload, timeout=5)
        if "syntax" in r.text.lower() or "mysql" in r.text.lower():
            print("[+] Muhtemel SQL Injection bulundu!")
        else:
            print("[-] SQL Injection tespit edilmedi.")
    except Exception as e:
        print(f"[!] Hata: {e}")

def xss_scanner(url):
    payload = "<script>alert(1)</script>"
    try:
        r = requests.get(url + payload, timeout=5)
        if payload in r.text:
            print("[+] XSS açığı bulundu!")
        else:
            print("[-] XSS tespit edilmedi.")
    except Exception as e:
        print(f"[!] Hata: {e}")

def port_scanner(host):
    print(f"[i] {host} için port taraması başlatıldı...")
    common_ports = [21,22,23,25,53,80,110,139,143,443,445,3389,8080,3306]
    for port in common_ports:
        try:
            s = socket.socket()
            s.settimeout(1)
            s.connect((host, port))
            print(f"[+] Port {port} açık!")
            s.close()
        except:
            pass

def dir_scanner(url):
    wordlist = ["admin","login","dashboard","config","backup","uploads","files"]
    for w in wordlist:
        try:
            r = requests.get(url+"/"+w, timeout=5)
            if r.status_code == 200:
                print(f"[+] Dizin bulundu: {url}/{w}")
        except:
            pass

def subdomain_finder(domain):
    subs = ["www","mail","ftp","test","dev","staging","beta","portal"]
    for s in subs:
        try:
            host = f"{s}.{domain}"
            socket.gethostbyname(host)
            print(f"[+] Subdomain bulundu: {host}")
        except:
            pass

def header_scan(url):
    try:
        r = requests.get(url, timeout=5)
        print("[i] Header bilgileri:")
        for k,v in r.headers.items():
            print(f"  {k}: {v}")
    except Exception as e:
        print(f"[!] Hata: {e}")

def ssl_check(url):
    try:
        host = urllib.parse.urlparse(url).hostname
        context = ssl.create_default_context()
        with socket.create_connection((host, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                print("[+] SSL sertifikası mevcut!")
                print(cert)
    except Exception as e:
        print("[-] SSL yok veya hata oluştu.", e)

def cors_check(url):
    try:
        r = requests.get(url, timeout=5)
        if "access-control-allow-origin" in r.headers:
            print("[+] CORS header bulundu, potansiyel açık")
        else:
            print("[-] CORS header yok")
    except:
        pass

def robots_scan(url):
    try:
        r = requests.get(url+"/robots.txt", timeout=5)
        print("[i] robots.txt içeriği:")
        print(r.text)
    except:
        pass

def sensitive_files(url):
    files = ["config.php",".env","backup.zip","db.sql"]
    for f in files:
        try:
            r = requests.get(url+"/"+f, timeout=5)
            if r.status_code==200:
                print(f"[+] Hassas dosya bulundu: {url}/{f}")
        except:
            pass

def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        print(w)
    except Exception as e:
        print("[!] Whois hatası:", e)

def geolocate(ip):
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap()
        print(json.dumps(res, indent=2))
    except Exception as e:
        print("[!] Geo IP hatası:", e)

def reverse_dns(ip):
    try:
        host = socket.gethostbyaddr(ip)
        print(host)
    except:
        print("[-] Reverse DNS bulunamadı")

def asn_lookup(ip):
    try:
        w = whois.whois(ip)
        if "asn" in w:
            print("[+] ASN:", w["asn"])
        else:
            print("[-] ASN bilgisi bulunamadı")
    except:
        print("[-] ASN bilgisi alınamadı")

def autoreporter(url):
    try:
        r = requests.get(url, timeout=5)
        if r.status_code==200:
            print("[+] Hedef canlı!")
        else:
            print("[-] Hedef yanıt vermiyor")
    except:
        print("[-] Hedef yanıt vermiyor")

def liveurl(url):
    try:
        r = requests.get(url, timeout=5)
        print(f"[i] HTTP durum kodu: {r.status_code}")
    except:
        print("[-] Hedef yanıt vermiyor")

def jwtinspect(url):
    try:
        r = requests.get(url, timeout=5)
        if "jwt" in str(r.headers).lower():
            print("[+] JWT token header bulundu!")
        else:
            print("[-] JWT token bulunamadı")
    except:
        print("[-] Hedef yanıt vermiyor")

def cspevaluator(url):
    try:
        r = requests.get(url, timeout=5)
        if "content-security-policy" in r.headers:
            print("[+] CSP Header bulundu!")
            print(r.headers["content-security-policy"])
        else:
            print("[-] CSP header yok")
    except:
        print("[-] Hedef yanıt vermiyor")

def emailharvest(url):
    try:
        r = requests.get(url, timeout=5)
        emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}", r.text)
        for e in set(emails):
            print(f"[+] Email bulundu: {e}")
    except:
        print("[-] Hedef yanıt vermiyor")

def sitecrawler(url):
    try:
        r = requests.get(url, timeout=5)
        links = re.findall(r'href=[\'"]?([^\'" >]+)', r.text)
        for l in set(links):
            print(f"[+] Link bulundu: {l}")
    except:
        print("[-] Hedef yanıt vermiyor")

# ---------------- Modül Çalıştırıcı ---------------- #
def run_module():
    module = options["module"]
    url = options["url"]
    if not module:
        print("[!] Önce modül seç")
        return
    host = url.replace("http://","").replace("https://","").split("/")[0] if url else None
    mapping = {
        "sqli": sqli_scanner,
        "xss": xss_scanner,
        "portscan": port_scanner,
        "dirscan": dir_scanner,
        "subfinder": subdomain_finder,
        "headerscan": header_scan,
        "sslcheck": ssl_check,
        "corscheck": cors_check,
        "robots_scan": robots_scan,
        "sensitivefiles": sensitive_files,
        "whoislookup": whois_lookup,
        "geolocate": geolocate,
        "reversedns": reverse_dns,
        "asnlookup": asn_lookup,
        "autoreporter": autoreporter,
        "liveurl": liveurl,
        "jwtinspect": jwtinspect,
        "cspevaluator": cspevaluator,
        "emailharvest": emailharvest,
        "sitecrawler": sitecrawler
    }
    func = mapping.get(module)
    if func:
        if module in ["portscan","subfinder","whoislookup","geolocate","reversedns","asnlookup"]:
            func(host)
        else:
            func(url)
    else:
        print("[!] Geçersiz modül")

# ---------------- Konsol ---------------- #
def main():
    print(banner)
    help_menu()
    while True:
        cmd = input("slopeorfyorf > ").strip()
        if cmd=="help": help_menu()
        elif cmd=="exit": break
        elif cmd=="show modules": show_modules()
        elif cmd.startswith("use "):
            mod = cmd.split(" ")[1]
            if mod in module_list:
                options["module"] = mod
                print(f"[i] Modül seçildi: {mod}")
            else:
                print("[!] Geçersiz modül")
        elif cmd.startswith("set url "):
            url = cmd.split(" ")[2]
            options["url"] = url
            print(f"[i] URL ayarlandı: {url}")
        elif cmd=="show options": show_options()
        elif cmd=="run": run_module()
        elif cmd=="back":
            options["module"] = None
            print("[i] Modülden çıkıldı")
        else:
            print("[!] Bilinmeyen komut. 'help' yazabilirsin")

if __name__=="__main__":
    main()
