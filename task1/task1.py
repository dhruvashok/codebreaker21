import ipaddress
import json

packets = json.loads(open("packets.json").read())
ips = [i.strip() for i in open("ip_ranges.txt").readlines()]
bad_ips = set()

for i in packets:
	src_ip = i["_source"]["layers"]["ip"]["ip.src_host"]
	dst_ip = i["_source"]["layers"]["ip"]["ip.dst_host"]
	for nets in ips:
		if ipaddress.ip_address(src_ip) in ipaddress.ip_network(nets):
			bad_ips.add(src_ip)
		if ipaddress.ip_address(dst_ip) in ipaddress.ip_network(nets):
			bad_ips.add(dst_ip)

for ip in bad_ips:
	print(ip)