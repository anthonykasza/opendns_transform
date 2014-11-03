''' 
Copyright (c) 2014, OpenDNS, Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
'''

import sys
import requests
import json

from MaltegoTransform import *

api_url = 'https://investigate.api.opendns.com'		# OpenDNS Investigate API URL
api_key = '' 						# OpenDNS Investigate API key. Obtain from OpenDNS.
headers = {'Authorization': 'Bearer ' + api_key}

class NoContentAPI(Exception):
    def __init__(self, message, suggestion):
        self.message = message
        self.suggestion = suggestion

class GenericErrorAPI(Exception):
    def __init__(self, message, suggestion):
        self.message = message
        self.suggestion = suggestion

def call_api(url):
    try:
        resp = requests.get(url, headers=headers)
    except:
        raise GenericErrorAPI(message="Could not send request to OpenDNS API", 
            suggestion="Ensure API key is correct, requests python library is installed, and machine has network connectivity")
    if resp.status_code == 204:
        raise NoContentAPI(message="OpenDNS API returned: 204 No Content.", suggestion="Try a different domain name")
    elif resp.status_code != 200:
        raise GenericErrorAPI(message="OpenDNS API returned: %s" % (resp.status_code), suggestion="Ensure API key is correct")
    elif json.loads(resp.content) == {}:
        raise GenericErrorAPI(message="OpenDNS API returned an empty response", suggestion="Try again or try a different domain/ip")
    else:
        return json.loads(resp.content)

def domain_to_attributes(entity, name):
    url = api_url + '/domains/categorization/%s?showLabels' % (name)
    status_index = {-1:"Blacklisted", 0:"Unknown", 1:"Whitelisted"}
    if name.endswith('.'):
        name = name[:-1]
    r = call_api(url)
    if name not in r:
        raise
    if 'status' not in r[name] or 'security_categories' not in r[name] or 'content_categories' not in r[name]:
        raise GenericErrorAPI(message="OpenDNS API returned invalid results from domain_to_attributes function", 
            suggestion="Ensure API key is correct")
    entity.addAdditionalFields("Status", "Status", "static", status_index[r[name]['status']])
    entity.addAdditionalFields("Security Category", "Security Category", "static", ','.join(r[name]['security_categories']))
    entity.addAdditionalFields("Content Category", "Content Category", "static", ','.join(r[name]['content_categories']))
    return mt

def domain_to_cooccurences(mt, name):
    url = api_url + '/recommendations/name/%s.json' % (name)
    if name.endswith('.'):
        name = name[:-1]
    try:
        r = call_api(url)
        if 'pfs2' not in r:
            raise GenericErrorAPI(message="OpenDNS API returned invalid results from domain_to_cooccurences function", 
                suggestion="Ensure API key is correct")
        for each in r['pfs2']:
            [domain, score] = each
            entity = mt.addEntity(enType="maltego.Domain", enValue="%s" % (domain))
            domain_to_attributes(entity, name)
    except (NoContentAPI, GenericErrorAPI) as e:
        mt.addUIMessage(message="%s" % (e.message), messageType="PartialError")
        mt.addUIMessage(message="%s" % (e.suggestion), messageType="PartialError")
    else:
        e = sys.exc_info()[0]
        mt.addUIMessage(message="%s" % e, messageType="PartialError")
    return mt

def domain_to_related_domains(mt, name):
    url = api_url + '/links/name/%s.json' % (name)
    if name.endswith('.'):
        name = name[:-1]
    try:
        r = call_api(url)
        if 'tb1' not in r:
            raise GenericErrorAPI(message="OpenDNS API returned invalid results from domain_to_related_domains function",
                suggestion="Ensure API key is correct")
        for each in r['tb1']:
            [domain, score] = each
            entity = mt.addEntity(enType="maltego.Domain", enValue="%s" % (domain))
            domain_to_attributes(entity, name)
    except (NoContentAPI, GenericErrorAPI) as e:
        mt.addUIMessage(message="%s" % (e.message), messageType="PartialError")
        mt.addUIMessage(message="%s" % (e.suggestion), messageType="PartialError")
    else:
        e = sys.exc_info()[0]
        mt.addUIMessage(message="%s" % e, messageType="PartialError")
    return mt

def domain_to_ips(mt, name):
    url = api_url + '/dnsdb/name/a/%s.json' % (name)
    if name.endswith('.'):
        name = name[:-1]
    try:
        r = call_api(url)
        for tf in r['rrs_tf']:
            for rrs in tf['rrs']:
                if rrs['class'] == 'IN' and rrs['type'] == 'A':
                    entity = mt.addEntity(enType="maltego.IPv4Address", enValue="%s" % (rrs['rr']))
    except (NoContentAPI, GenericErrorAPI) as e:
        mt.addUIMessage(message="%s" % (e.message), messageType="PartialError")
        mt.addUIMessage(message="%s" % (e.suggestion), messageType="PartialError")
    else:
        e = sys.exc_info()[0]
        mt.addUIMessage(message="%s" % e, messageType="PartialError")
    return mt

def domain_to_asns(mt, name):
    url = api_url + '/dnsdb/name/a/%s.json' % (name)
    if name.endswith('.'):
        name = name[:-1]
    try:
        r = call_api(url)
        if 'features' not in r:
            raise GenericErrorAPI(message="No data found for domain name", suggestion="Try a different domain")
        if 'asns' not in r['features']:
            raise GenericErrorAPI(message="No data found for domain name", suggestion="Try a different domain")
        for asn in r['features']['asns']:
            mt.addEntity(enType="maltego.AS", enValue="asn: %s" % (asn))
    except (NoContentAPI, GenericErrorAPI) as e:
        mt.addUIMessage(message="%s" % (e.message), messageType="PartialError")
        mt.addUIMessage(message="%s" % (e.suggestion), messageType="PartialError")
    else:
        e = sys.exc_info()[0]
        mt.addUIMessage(message="%s" % e, messageType="PartialError")
    return mt

def domain_to_ns_ips(mt, name):
    url = api_url + '/dnsdb/name/ns/%s.json' % (name)
    if name.endswith('.'):
        name = name[:-1]
    try:
        r = call_api(url)
        if 'rrs_tf' not in r:
            raise  GenericErrorAPI(message="OpenDNS API returned invalid results from domain_to_attributes function",
                suggestion="Ensure API key is correct")
        for tf in r['rrs_tf']:
            for rrs in tf['rrs']:
                if rrs['class'] == 'IN' and rrs['type'] == 'NS':
                    mt.addEntity(enType="maltego.NSRecord", enValue="%s" % (rrs['rr']))
    except (NoContentAPI, GenericErrorAPI) as e:
        mt.addUIMessage(message="%s" % (e.message), messageType="PartialError")
        mt.addUIMessage(message="%s" % (e.suggestion), messageType="PartialError")
    else:
        e = sys.exc_info()[0]
        mt.addUIMessage(message="%s" % e, messageType="PartialError")
    return mt

def ip_to_domains(mt, ip):
    url = api_url + '/dnsdb/ip/a/%s.json' % (ip)
    try:
        r = call_api(url)
        if 'rrs' not in r:
            raise GenericErrorAPI(message="OpenDNS API returned invalid results from ip_to_domains function",
                suggestion="Ensure API key is correct")
        for each in r['rrs']:
            if each['class'] == 'IN' and each['type'] == 'A':
                name = each['rr']
                if name.endswith('.'):
                    name = name[:-1]
                entity = mt.addEntity(enType="maltego.Domain", enValue="%s" % (name))
                domain_to_attributes(entity, name)
    except (NoContentAPI, GenericErrorAPI) as e:
        mt.addUIMessage(message="%s" % (e.message), messageType="PartialError")
        mt.addUIMessage(message="%s" % (e.suggestion), messageType="PartialError")
    else:
        e = sys.exc_info()[0]
        mt.addUIMessage(message="%s" % e, messageType="PartialError")
    return mt


handlers = {
	'domain_to_cooccurences':	domain_to_cooccurences,
	'domain_to_related_domains':	domain_to_related_domains,
	'domain_to_ips':		domain_to_ips,
	'domain_to_asns':		domain_to_asns,	
	'domain_to_ns_ips':		domain_to_ns_ips,
	'ip_to_domains':		ip_to_domains,
}

if __name__ == '__main__':
    transform = sys.argv[1]
    input = sys.argv[2]
    
    mt = MaltegoTransform()
    mt = handlers[transform](mt, input)
    mt.returnOutput()
