from bs4 import BeautifulSoup
from collections import defaultdict
from netaddr import IPNetwork, IPAddress

import gzip
import logging
import requests


CAIDA_BASE_URL = "https://publicdata.caida.org/datasets/routing/routeviews-prefix2as"


class PrefixToAS:
    def __init__(self, year: int, month: int, day: int):
        self.year = str(year)
        self.month = f"{month:02d}"
        self.day = f"{day:02d}"
        self.date = self.year + self.month + self.day
        self.lookupMap = defaultdict(list)

    def download(self):
        """
        Download the correct routeview file from CAIDA based on the provided date.
        The base url for the files is: https://publicdata.caida.org/datasets/routing/routeviews-prefix2as
        """
        file_url = f"{CAIDA_BASE_URL}/{self.year}/{self.month}/"

        # Figure out the exact file location
        soup = BeautifulSoup(requests.get(file_url).content, 'html.parser')
        for a in soup.find_all('a', href=True):
            if 'routeviews-' in a['href'] and self.date in a['href'] and a['href'].endswith('.gz'):
                file_url += a['href']
                break

        if not file_url.endswith('.gz'):
            raise ValueError(f"Could not find routeviews file for {self.date}")

        logging.debug(f"Downloading: {file_url}")
        routeviews_data = gzip.decompress(requests.get(file_url).content)

        # Construct lookup hashmap based on the first octet, reducing the overall number of checks needed.
        self.lookupMap = defaultdict(list)
        for row in routeviews_data.decode('utf-8').split("\n"):
            if len(row.strip()) == 0:
                continue

            ip, subnet, ases = row.split("\t")
            first_octet = ip.split('.')[0]
            self.lookupMap[first_octet].append((IPNetwork(f"{ip}/{subnet}"), ases))

        return self

    def lookup(self, ip: str) -> list:
        """
        Lookup an IP address and return all matching AS numbers for the specific date.
        :param ip: String containing the IP address
        :return: List of ASes corresponding to that IP address.
        """
        ipaddress = IPAddress(ip)
        first_octet = ip.split('.')[0]
        matches = set()
        for network, ases in self.lookupMap[first_octet]:
            if ipaddress in network:
                matches.add(ases)
        return list(matches)
