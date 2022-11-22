#!/usr/bin/env python3

from watchtower import WatchtowerModule


class SampleModule(WatchtowerModule):
    def run(self, args):
        parse_args(args)
        password = self.get_config_value('password')
        print(f"Configuration file: password = {password}")
        check_password(password)
        response = {
            "tables": {
                "devices": {
                    "rows": get_devices(),
                    "pk": "mac"
                },
                "services": {
                    "rows": get_services(),
                }
            }
        }
        return response


def parse_args(args):
    if args:
        first_arg = args[0]
        if first_arg == "help":
            exit("I don't feel like writing a help file.")
        print(f"First argument: {first_arg}")
        if len(args) > 1:
            second_arg = args[1]
            print(f"Second argument: {second_arg}")


def check_password(password):
    if password == "12345":
        print(f"That's amazing, I've got the same combination on my luggage!")


def get_devices():
    devices = []
    for i in range(1, 51):
        hexstr = hex(i)[2:]
        hexstr = f"0{hexstr}" if len(hexstr) == 1 else hexstr
        mac = f"6F:30:7D:44:12:{hexstr}"
        hostname = f"linux-server-{i}"
        ip = f"10.0.0.{i}"
        device = {"mac": mac, "hostname": hostname, "ip": ip}
        devices.append(device)
    return devices


def get_services():
    services = []
    for i in range(1, 51):
        ip = f"10.0.0.{i}"
        for j in (21, 22, 443, 3306):
            port = j
            protocol = "tcp"
            banner = {
                "21": "ProFTPD 1.3.6d Server",
                "22": "SSH-2.0-OpenSSH_8.2",
                "443": "Apache/2.4.43",
                "3306": "MySQL 8.0.20",
            }.get(str(j))
            service = {"ip": ip, "port": port, "protocol": protocol, "banner": banner}
            services.append(service)
    return services
