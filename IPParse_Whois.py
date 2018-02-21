import ipaddress
import pprint
from ipwhois import IPWhois,exceptions
import re

class IPimport:

    def __init__(self, configfile):
        self.configfile = configfile

    def readfile(self):

        ## Read the objects file and produce a list

        f = open(self.configfile, 'r')

        self.addresslist = []
        self.whoisdic = {}
        seen = set()        

        for line in f:
            line = re.sub(r'\n$','', line)
            words = line.split(' ')
            for i in words:
                if i not in seen:
                    try:
                        ip = ipaddress.IPv4Address(i)
                        self.addresslist.append(ip)
                        seen.add(i)
                    except ipaddress.AddressValueError as e:
                        seen.add(i)

        f.close()

        return self.addresslist

    def whoislookup(self, addresslist):

        self.addresslist = addresslist

        for i in self.addresslist:
            if ipaddress.IPv4Address(i).is_global:
                i = str(i)
                self.whoissubdic = {}
                
                try:
                    self.iwhois = IPWhois(i).lookup_rdap(depth=1)
                    if self.iwhois['asn_country_code']:
                        self.whoissubdic['asn_country_code'] = self.iwhois['asn_country_code']
                    else:
                        self.whoissubdic['asn_country_code'] = 'Null'

                    if self.iwhois['asn_description']:
                        self.whoissubdic['asn_description'] = self.iwhois['asn_description']
                    else:
                        self.whoissubdic['asn_description'] = 'Null'
                        
                    self.whoissubdic['error'] = 'Null'
                    
                    try:
                        self.whoissubdic['description'] = self.iwhois['network']['remarks'][0]['description']
                        
                    except TypeError:
                        self.whoissubdic['description'] = 'Null'
                    
                except exceptions.IPDefinedError as e:
                    self.whoissubdic['error'] = e
                except exceptions.HTTPLookupError as e:
                    self.whoissubdic['error'] = e
                except exceptions.HTTPLookupError as e:
                    self.whoissubdic['error'] = e
                except:
                    print('Unknown error with - {}'.format(i))

                self.whoisdic[i] = self.whoissubdic
                
        return self.whoisdic


    def whoissingle(self, address):

        self.address = address

        return IPWhois(address).lookup_rdap(depth=1)


cf = IPimport('configfile.txt')
addresslist = cf.readfile()

whoisout = cf.whoislookup(addresslist)
for i in whoisout:
    try:
        print('\"{}\",    \"{}\",  \"{}\",  \"{}\",  \"{}\"'.format(str(i), whoisout[i]['asn_country_code'], whoisout[i]['asn_description'], re.sub(r'\n', ', ', whoisout[i]['description']), whoisout[i]['error'],))
    except KeyError:
        print('Error: {}'.format(whoisout[i]))
