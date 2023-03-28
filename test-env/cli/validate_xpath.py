import sys
import os
import xml.etree.ElementTree as ET
import json
from lxml import etree

# validate_xpath.py test-dir testID AOID date ONLINE_ENABLED

print("input: %s | %s | %s | %s | %s" % (sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]))
tstDIR=sys.argv[1]
tstID=sys.argv[2]
AOID=sys.argv[3]
cDate=sys.argv[4]

IsOnlEnabled=False
if sys.argv[5] == "YES":
  IsOnlEnabled= True

nsmap = {'ns1':'urn:oasis:names:tc:dss-x:1.0:profiles:verificationreport:schema#',
         'ns2':'http://www.w3.org/2000/09/xmldsig#', 
         'ns3':'urn:oasis:names:tc:dss:1.0:core:schema',
         'ns4':'urn:oasis:names:tc:dss-x:1.0:profiles:encryption:schema#',
         'ns5':'http://www.bsi.bund.de/ecard/api/1.1',
         'ns6':'urn:iso:std:iso-iec:24727:tech:schema',
         'ns7':'http://www.setcce.org/schemas/ers',
         'ns8':'http://uri.etsi.org/01903/v1.3.2#',
         'ns9':'http://www.bsi.bund.de/tr-esor/vr'}

if IsOnlEnabled:
  reportOnlFN = './'+tstDIR+'/'+cDate+'-online-output/'+AOID+'/'+tstID+'-ONL-report.xml'
  print("[i] online report path: %s" % reportOnlFN)
reportOflFN = './'+tstDIR+'/'+cDate+'-offline-output/'+AOID+'/'+tstID+'-OFF-report.xml'
print("[i] offline report path: %s" % reportOflFN)

expOnl='./'+tstDIR+'/'+tstID+'-tf-exp-onl.txt'
expOfl='./'+tstDIR+'/'+tstID+'-tf-exp-off.txt'

gOnline=0
gOffline=0
gFailedOnline=0
gNotFoundOnline=0
gFailedOffline=0
gNotFoundOffline=0

if IsOnlEnabled:
    print("---------- Online part validation ------------")
    onlXMLDoc=etree.parse(reportOnlFN)
    onlRoot = onlXMLDoc.getroot()
     
    with open(expOnl) as json_file:
      expectedDataOnl = json.load(json_file)
     
    for k,v in expectedDataOnl.items():
      found = onlRoot.xpath( k, namespaces=nsmap )
      try:
        gOnline+=1
        if not found or len(found) == 0:
          print("XPATH NOT FOUND:")
          print(" |-Key: %s" % k)
          gNotFoundOnline+=1
          continue
        val = found[0].text 
        if  val == v:
          print("XPATH OK:")
          print(" |-Key: %s" % k)
          print(" |-Expected: %s" % v)
          print(" |-Obtained: %s" % val)
          continue
        else:
          print("!!!! XPATH NOK !!!!:")
          print(" |-Key: %s" % k)
          print(" |-Expected: %s" % v)
          print(" |-Obtained: %s" % val)
          gFailedOnline+=1
          continue
      except Exception as e:
        print ( "ERROR: couldn't obtain the specified value from repsonse, key: %s" % k);
        sys.exit()

print("---------- Offline part validation ------------")
oflXMLDoc=etree.parse(reportOflFN)
oflRoot = oflXMLDoc.getroot()

with open(expOfl) as json_file:
  expectedDataOfl = json.load(json_file)
  
for k,v in expectedDataOfl.items():
  found = oflRoot.xpath( k, namespaces=nsmap )
  try:
    gOffline+=1
    if not found or len(found) == 0:
      print("XPATH NOT FOUND:")
      print(" |-Key: %s" % k)
      gFailedOffline+=1
      continue
    val = found[0].text 
    if  val == v:
      print("XPATH OK:")
      print(" |-Key: %s" % k)
      print(" |-Expected: %s" % v)
      print(" |-Obtained: %s" % val)
      continue
    else:
      print("!!!! XPATH NOK !!!!:")
      print(" |-Key: %s" % k)
      print(" |-Expected: %s" % v)
      print(" |-Obtained: %s" % val)
      gFailedOffline+=1
      continue
  except Exception as e:
    print ( "ERROR: couldn't obtain the specified value from repsonse, key: %s" % k);
    sys.exit()
print("---------- GLOBAL EVALUATION RESULTS ----------")
gSuccOnline=gOnline-gFailedOnline-gNotFoundOnline
gRestOnline="NOK"
gSuccOffline=gOffline-gFailedOffline-gNotFoundOffline
gResOffline="NOK"
if gOnline == gSuccOnline:
  gRestOnline="OK"
if gOffline == gSuccOffline:
  gResOffline="OK"

if IsOnlEnabled: 
    print("--> Online  in total=",gOnline,"   FAILED=",gFailedOnline,"   NOT FOUND=",gNotFoundOnline,"   SUCCEED=",gSuccOnline, " => Result: ",gRestOnline)
print("--> Offline in total=",gOffline,"   FAILED=",gFailedOffline,"   NOT FOUND=",gNotFoundOffline,"   SUCCEED=",gSuccOffline, " => Result: ",gResOffline)