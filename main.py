import json
import nmap
import asyncio
from typing import List

async def scan(ip: str, ports: List[int]) -> dict:
    scanner = nmap.PortScanner()
    open_ports = []
    closed_ports = []
    results = scanner.scan(ip, ",".join(str(p) for p in ports))
    for port in results['scan'][ip]['tcp']:
        if results['scan'][ip]['tcp'][port]['state'] == 'open':
            open_ports.append(port)
        elif results['scan'][ip]['tcp'][port]['state'] == 'closed':
            closed_ports.append(port)
        else:
            print(f"Неизвестное состояние '{results['scan'][ip]['tcp'][port]['state']}' порта {port} на IP-адресе {ip}")
    return {'ip': ip, 'open_ports': open_ports, 'closed_ports': closed_ports}

async def run_scans(ips: List[str], ports: List[int]) -> List[dict]:
    tasks = []
    for ip in ips:
        tasks.append(asyncio.create_task(scan(ip, ports)))
        print(f"Сканирование IP-адреса {ip}...")
    return await asyncio.gather(*tasks)

if __name__ == '__main__':
    ips = ['192.168.0.1', '192.168.0.2', '192.168.0.3', '192.168.0.4', '192.168.0.5', '192.168.0.6', '192.168.0.7', '192.168.0.8', '192.168.0.9', '192.168.0.10']
    ports = [int(p) for p in open('ports.txt').read().split()]

    results = asyncio.run(run_scans(ips, ports))

    output = {}
    for result in results:
        output[result['ip']] = {'open_ports': result['open_ports']}
    output['closed_ports'] = []
    for port in ports:
        is_closed = True
        for result in results:
            if port in result['open_ports']:
                is_closed = False
                break
        if is_closed:
            output['closed_ports'].append(port)

    print(json.dumps(output))