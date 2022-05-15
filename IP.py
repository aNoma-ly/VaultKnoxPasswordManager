import json
import socket
from urllib.request import urlopen


class IPDetails:
    def __init__(self):
        try:
            hostname = socket.gethostname()
        except:
            hostname = "Unknown"
        try:
            localIP = socket.gethostbyname(hostname)
        except:
            localIP = "Unknown"

        try:
            url = 'http://ipinfo.io/json'
            response = urlopen(url)
            data = json.load(response)

            try:
                IP = data['ip']
            except:
                IP = "Unknown"
            try:
                org = data['org']
            except:
                org = "Unknown"
            try:
                city = data['city']
            except:
                city = "Unknown"
            try:
                country = data['country']
            except:
                country = "Unknown"
            try:
                region = data['region']
            except:
                region = "Unknown"
        except:
            IP = "Unknown"
            org = "Unknown"
            city = "Unknown"
            country = "Unknown"
            region = "Unknown"

        self.IP = IP
        self.org = org
        self.city = city
        self.country = country
        self.region = region
        self.hostname = hostname
        self.localIP = localIP
