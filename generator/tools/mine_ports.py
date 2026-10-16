#!/usr/bin/env python3
"""Mine the 952-file reference corpus for attested model->port-name evidence,
with attention to the industrial / IoT / maritime device families this project
needs.  Writes build/port_evidence.json.

Evidence tiers: corpus-link (a LINK names the port), corpus-ios (interface name
inside a RUNNINGCONFIG), template (the harvested template's own port inventory).
"""
import sys, glob, json, collections, os
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from yokohama_paths import bootstrap   # noqa: E402
_TOOLKIT = bootstrap()
import pt9
import xml.etree.ElementTree as ET

CORPUS = str(_TOOLKIT / 'corpus' / 'files')
OUT = str(Path(__file__).resolve().parent.parent / 'build' / 'port_evidence.json')
FAMILY = {'eCopperFastEthernet': 'FastEthernet', 'eCopperGigabitEthernet': 'GigabitEthernet',
          'eFiberGigabitEthernet': 'GigabitEthernet', 'eCopperEthernet': 'Ethernet',
          'eSmartSerial': 'Serial'}
INTEREST = ['IE-9320', 'IE-3400', 'IE-2000', 'IR1101', 'IR8340', 'ISA-3000', 'CGR1240',
            'PLC-PT', 'HMI-PT', 'RFID Reader', 'Metal Sensor', 'Motion Detector',
            'Temperature Sensor', 'Temperature Monitor', 'Humiture Monitor',
            'Generic Environment Sensor', 'NetworkController', 'MCU-PT', 'SBC-PT',
            'DataHistorianServer', 'CyberObserver', 'Beacon', 'Siren', 'Photo Sensor',
            'Smoke Detector', 'Trip Sensor', 'Wind Sensor', 'Water Level Monitor',
            'Street Lamp', 'Smart LED', 'Cell-Tower', 'Power Meter', 'LAP-PT',
            'TabletPC-PT', 'SMARTPHONE-PT', 'Central-Office-Server',
            'Power Distribution Device', 'Analog-Phone-PT', 'Home-VoIP-PT']

files = sorted(glob.glob(os.path.join(CORPUS, '**', '*.pkt'), recursive=True)) + \
        sorted(glob.glob(os.path.join(CORPUS, '**', '*.pka'), recursive=True))
portmap = collections.defaultdict(collections.Counter)
iosmap = collections.defaultdict(collections.Counter)
models_seen = collections.Counter()
ok = fail = 0
for f in files:
    try:
        xml = pt9.decode(f, 'pkt', verify_tag=False)
        root = ET.fromstring(xml)
    except Exception:
        fail += 1
        continue
    ok += 1
    for net in root.iter('NETWORK'):
        devs = {}
        for d in net.iter('DEVICE'):
            sid = d.findtext('ENGINE/SAVE_REF_ID')
            t = d.findtext('ENGINE/TYPE') or ''
            import re
            mm = re.search(r'model="([^"]*)"', t)
            mdl = mm.group(1) if mm else t
            if sid:
                devs[sid] = mdl
                models_seen[mdl] += 1
        for lk in net.iter('LINK'):
            cab = lk.find('CABLE')
            if cab is None:
                continue
            fr, to = cab.findtext('FROM'), cab.findtext('TO')
            for end, other in ((fr, to), (to, fr)):
                if end in devs:
                    p = cab.findtext('PORT')
                    # PORT is repeated: first is FROM's, second is TO's
                    ports = [e.text for e in cab.findall('PORT')]
                    if len(ports) >= 2:
                        p = ports[0] if end == fr else ports[1]
                    portmap[devs[end]][p] += 1
    for d in root.iter('DEVICE'):
        t = d.findtext('ENGINE/TYPE') or ''
        import re
        mm = re.search(r'model="([^"]*)"', t)
        mdl = mm.group(1) if mm else t
        for line in d.iter('LINE'):
            import re as _re
            m2 = _re.match(r'^interface ((?:Gigabit|Fast|TenGigabit|Ethernet)[\d/\.]*)$', (line.text or '').strip())
            if m2:
                iosmap[mdl][m2.group(1)] += 1
print(f'decoded {ok} ok / {fail} failed')
res = {'_meta': {'files_ok': ok, 'files_failed': fail},
       'link': {m: dict(c) for m, c in portmap.items()},
       'ios': {m: dict(c) for m, c in iosmap.items()},
       'models_seen': dict(models_seen.most_common())}
with open(OUT, 'w') as fh:
    json.dump(res, fh, indent=1, sort_keys=True)
print('--- models of interest ---')
for m in INTEREST:
    lk = sorted(portmap.get(m, {}))
    io = sorted(iosmap.get(m, {}))
    print(f'{m:30s} seen={models_seen.get(m,0):5d}  link={lk[:10]}  ios={io[:8]}')
print('--- all models seen:', len(models_seen))
