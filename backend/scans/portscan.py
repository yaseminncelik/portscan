import subprocess
from datetime import datetime
import re
import ipaddress

ip_file = 'ips.txt'
log_file = 'tarama_sonuclari.log'
rustscan_path = r'"C:\Program Files\RustScan\rustscan.exe"'  # RustScan yolu, Windows için örnek
nmap_args = "-sS -Pn -T4"  # SYN tarama, ping atma ve hızlı tarama

populer_tcp_portlar = [
    20, 21, 22, 23, 25, 53, 80, 110, 111, 119, 123, 135, 139, 143, 161,
    389, 443, 445, 465, 514, 587, 631, 636, 873, 989, 990, 993, 995, 1080,
    1194, 1433, 1434, 1521, 1723, 2049, 2121, 2483, 2484, 3306, 3389, 3690,
    4444, 4711, 5040, 5432, 5631, 5900, 5985, 5986, 6379, 6667, 7680, 8080,
    8443, 8888, 9100, 10000, 11211, 27017, 28017, 50000, 49152, 49153, 49154,
    49155, 49156, 49157
]

def log_yaz(metin: str):
    with open(log_file, 'a', encoding='utf-8') as log:
        log.write(metin + '\n')

def ipleri_genislet(ip_satiri):
    try:
        if '/' in ip_satiri:
            ag = ipaddress.IPv4Network(ip_satiri, strict=False)
            return [str(ip) for ip in ag.hosts()]
        else:
            return [ip_satiri]
    except Exception as e:
        print(f"Geçersiz IP/CIDR atlandı: {ip_satiri} ({e})", flush=True)
        return []

try:
    with open(ip_file, 'r', encoding='utf-8') as file:
        for line in file:
            line = line.strip()
            if not line or ',' not in line:
                continue
            try:
                ip_raw, port_start, port_end = [x.strip() for x in line.split(',')]
                port_range = f"{port_start}-{port_end}"
                ip_list = ipleri_genislet(ip_raw)
            except ValueError:
                print(f"Satır hatalı atlandı: {line}", flush=True)
                continue

            for ip in ip_list:
                print(f"\n# Tarama başlıyor: {ip} (Port aralığı: {port_range})", flush=True)

                port_start_num = int(port_start)
                port_end_num = int(port_end)

                # Belirtilen port aralığı taraması
                command_aralik = f'{rustscan_path} -a {ip} --ulimit 5000 --range {port_range} -- {nmap_args}'
                result = subprocess.run(command_aralik, shell=True, capture_output=True, encoding='utf-8')

                if result.returncode == 0:
                    lines = result.stdout.strip().splitlines()
                    start_printing = False
                    for line in lines:
                        if re.match(r"PORT\s+STATE\s+SERVICE", line):
                            start_printing = True
                            continue
                        if start_printing:
                            match = re.match(r"(\d+)/(tcp|udp)\s+open\s+(\S+)", line)
                            if match:
                                port = match.group(1)
                                protokol = match.group(2)
                                service = match.group(3)
                                now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                                log_line = (
                                    f"time={now} , host={ip} ,port={port} protokol={protokol} , "
                                    f"port_durumu=open , service={service}"
                                )
                                print(log_line, flush=True)
                                log_yaz(log_line)
                else:
                    print(f"Hata oluştu ({ip}): {result.stderr.strip()}", flush=True)

                # Popüler portlar, belirlenen aralığın dışındakiler
                extra_ports = [str(p) for p in populer_tcp_portlar if p < port_start_num or p > port_end_num]
                if extra_ports:
                    extra_ports_str = ",".join(extra_ports)
                    print(f"\n# Ekstra popüler portlar taranıyor: {extra_ports_str}", flush=True)
                    command_extra = f'{rustscan_path} -a {ip} --ulimit 5000 --ports {extra_ports_str} -- {nmap_args}'
                    result_extra = subprocess.run(command_extra, shell=True, capture_output=True, encoding='utf-8')

                    if result_extra.returncode == 0:
                        lines = result_extra.stdout.strip().splitlines()
                        start_printing = False
                        for line in lines:
                            if re.match(r"PORT\s+STATE\s+SERVICE", line):
                                start_printing = True
                                continue
                            if start_printing:
                                match = re.match(r"(\d+)/(tcp|udp)\s+open\s+(\S+)", line)
                                if match:
                                    port = match.group(1)
                                    protokol = match.group(2)
                                    service = match.group(3)
                                    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                                    log_line = (
                                        f"time={now} , host={ip} ,port={port} protokol={protokol} , "
                                        f"port_durumu=open , service={service}"
                                    )
                                    print(log_line, flush=True)
                                    log_yaz(log_line)
                    else:
                        print(f"Hata oluştu (ekstra portlar - {ip}): {result_extra.stderr.strip()}", flush=True)

except Exception as e:
    print(f"Bir hata oluştu: {e}", flush=True)
