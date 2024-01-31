#
# Convert info found in ViGuide Demo to list of datapoints and list of writables

import json

didsAll = {}
didsPerDev = {}
didsWritable = {'all': {}}
cntDps = 0
cntWrt = {'all': 0}
cntDpsPerDev = {}

def str2int(s):
    return int(s)

def sortDict(d):
    # return dict d sorted by numeric value of key
    myKeys = list(d.keys())
    myKeys.sort(key = str2int)
    return {i: d[i] for i in myKeys}

print('Start collection datapoints for all devices.')

f = open('vddList.json')
vddList = json.load(f)
f.close()

for item in vddList['vddList'].values():
    devSplit = item['data']['ecu'].split('_')
    dev = devSplit[2]+'_'+devSplit[3]
    cntDpsPerDev[dev] = 0
    didsPerDev[dev] = {}
    for did in item['data']['structure'][0]['structure']:
        id = did['interval']
        idStr = did['texttableentry']

        if not id in didsAll:
            cntDps += 1
            didsAll[id] = {
                'idStr': idStr,
                'devs': {},
                }
        cntDpsPerDev[dev] += 1
        didsAll[id]['devs'][dev] = {'len': 0, 'writable': did['isWrite'], 'codec': {}}
        didsPerDev[dev][id] = idStr

        if did['isWrite']=='true':
            if not dev in didsWritable:
                didsWritable[dev] = {}
                cntWrt[dev] = 0
            cntWrt[dev] += 1
            didsWritable[dev][id] = idStr
            if not id in didsWritable['all']:
                cntWrt['all'] += 1
                didsWritable['all'][id] = idStr

didsWritable['all'] = sortDict(didsWritable['all'])
didsWritable['cnts'] = cntWrt

didsPerDev['cnts'] = cntDpsPerDev

with open('Open3E_didsAllDevs.json', 'w') as json_file:
    json.dump(sortDict(didsAll), json_file, indent=2)

with open('Open3E_didsPerDevs.json', 'w') as json_file:
    json.dump(didsPerDev, json_file, indent=2)

with open('Open3Edatapoints_writablesAllDevs.json', 'w') as json_file:
    json.dump(didsWritable, json_file, indent=2)

print('Dids found per device:')
print(cntDpsPerDev)
print('Writables found per device:')
print(cntWrt)
print('Done.')
