A local transform for Maltego which makes use of the Investigate API by OpenDNS

Installation
------------
1. Install [Python](https://www.python.org/downloads/). This transform was developed and tested with Python 2.7
2. Install the [requests](http://docs.python-requests.org/en/latest/user/install/#install) Python library.
3. Download and install the commercial version of [Maltego](https://www.paterva.com/web6/products/download.php).

Configuration
-------------
1. Clone this repository to a local directory (referred to as the 'working directory' in Maltego parlance).
2. Obtain an [OpenDNS Investigate](http://www.opendns.com/enterprise-security/solutions/investigate/) API key.
3. Place the API key in the OpenDNStransform.py file.
4. Import OpenDNS-config-carbon.mtz as a Maltego configuration file
5. Set the working directory of each transform (which should be set to /opt/maltego/opendns_transform by default) to the working directory from step 1.
6. Ensure each transform has the proper Python path.

Tips
----
- OpenDNS transforms only work on Domain and IP entities. For example, before running a transform on an NSrecord entity, change that entity's type to IPv4Address.
- OpenDNS transforms produce Domain, IPv4Address, NSRecord, and AS entity types.
- Some OpenDNS transforms (like domain-to-ips and ip-to-domains) potentially return a large number of entities
    - be patience, the transform has to receive all data from the API before it draws it in Maltego
    - be aware of the maximum number of results (entities/nodes) allowed on your graph (12, 50, 255, 10k)

