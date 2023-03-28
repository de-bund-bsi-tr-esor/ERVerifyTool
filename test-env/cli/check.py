import sys
import xml.etree.ElementTree as ET
import json
from lxml import etree

# check.py test-name test-descr online-result online-exp offline-result off-exp OL PROFILE ONLINE_ENABLED

IsOnlEnabled=False
if sys.argv[9] == "YES":
  IsOnlEnabled= True

_file = open(sys.argv[9], 'a')
_file.write('|¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯|\n')
_file.write('|-> [' + sys.argv[1] + ']\n')
_file.write('|-> ' + sys.argv[2] + '\n')

resultLinePre = sys.argv[7] + ';'
if sys.argv[2].startswith('[+]'):
  resultLinePre += 'p;'
else:
  resultLinePre += 'n;'
resultLinePre += sys.argv[1] + ';'

resultLine = resultLinePre

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
    _file.write('|---------------------------------------------------------------------------|\n')
    _file.write('|                                  ONLINE                                   |\n')
    _file.write('|---------------------------------------------------------------------------|\n')
    resultLine += 'ONLINE;' + sys.argv[8] + ';'


    tree = etree.parse(sys.argv[3])
    root = tree.getroot()

    with open(sys.argv[4]) as json_file:
      expectedData = json.load(json_file)

    rv = ['PASSED', 'empty', 'empty', 'empty'];
    for k,v in expectedData.items():
      found = root.xpath( k, namespaces=nsmap )
      try:
        if not found or len(found) == 0:
          rv[0] = 'FAILED';
          rv[1] = k
          rv[2] = v
          rv[3] = "NOT FOUND!"
          continue
        val = found[0].text 
        if  val == v:
          continue
        else:
          rv[0] = 'FAILED';
          rv[1] = k
          rv[2] = v
          rv[3] = val
      except Exception as e:
        print ( "ERROR: couldn't obtain the specified value from repsonse, key: %s" % k);
        sys.exit()
    if rv[0] == 'PASSED':
      _file.write('| Test case in total: >>> PASSED <<<                                        |\n')
      resultLine += 'PASSED;'
    else:
      _file.write('| Test case in total: >>> FAILED <<<                                        |\n')
      _file.write('  Key:      ' + rv[1] + '\n')
      _file.write('  Expected: ' + rv[2] + '\n')
      _file.write('  Obtained: ' + rv[3] + '\n')
      resultLine += 'FAILED;'
  
    resultLine += sys.argv[2] + ';;'
    print(resultLine)

resultLine = resultLinePre
resultLine += 'OFFLINE;' + sys.argv[8] + ';'
  
_file.write('|---------------------------------------------------------------------------|\n')
_file.write('|                                  OFFLINE                                  |\n')
_file.write('|---------------------------------------------------------------------------|\n')

tree = etree.parse(sys.argv[5])
root = tree.getroot()

with open(sys.argv[6]) as json_file:
  expectedData = json.load(json_file)

rv = ['PASSED', 'empty', 'empty', 'empty'];
for k,v in expectedData.items():
  found = root.xpath( k, namespaces=nsmap )
  try:
    if not found or len(found) == 0:
      rv[0] = 'FAILED';
      rv[1] = k
      rv[2] = v
      rv[3] = "NOT FOUND!"
      continue
    val = found[0].text 
    if  val == v:
      continue
    else:
      rv[0] = 'FAILED';
      rv[1] = k
      rv[2] = v
      rv[3] = val
  except Exception as e:
    print ( "ERROR: couldn't obtain the specified value from repsonse, key: %s" % k);
    sys.exit()
if rv[0] == 'PASSED':
  _file.write('| Test case in total: >>> PASSED <<<                                        |\n')
  resultLine += 'PASSED;'
else:
  _file.write('| Test case in total: >>> FAILED <<<                                        |\n')
  _file.write('  Key:      ' + rv[1] + '\n')
  _file.write('  Expected: ' + rv[2] + '\n')
  _file.write('  Obtained: ' + rv[3] + '\n') 
  resultLine += 'FAILED;'
_file.write('|___________________________________________________________________________|\n\n')

resultLine += sys.argv[2] + ';;'
print(resultLine)

