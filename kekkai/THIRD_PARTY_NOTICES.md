# Third-party notices

KEKKAI itself is released under the Unlicense (see the repository LICENSE). It bundles or downloads the
following third-party data.

## Bundled: `src/kekkai/web/data/world.json`

Derived (antimeridian-cut, rounded, Antarctica removed, Japanese names added) from:

### Natural Earth — Admin 0 countries 1:110m
Public domain. https://www.naturalearthdata.com/

### world-atlas 2.0.2 (TopoJSON redistribution of Natural Earth)

```
Copyright 2013-2019 Michael Bostock

Permission to use, copy, modify, and/or distribute this software for any purpose
with or without fee is hereby granted, provided that the above copyright notice
and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
THIS SOFTWARE.
```

### i18n-iso-countries 7.14.0 (ISO 3166 codes and Japanese country names)

```
The MIT License (MIT)

Copyright (c) 2016 widdix GmbH

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the
following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial
portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO
EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
OR OTHER DEALINGS IN THE SOFTWARE.
```

## Downloaded at runtime (not redistributed)

| Data | Source | Terms |
|---|---|---|
| IP geolocation / ASN | DB-IP Lite (download.db-ip.com, fallback: jsDelivr npm mirrors) | CC BY 4.0 — "IP Geolocation by DB-IP" (shown in the dashboard) |
| MAC vendors | IEEE Registration Authority (fallback: npm `oui-data`) | IEEE public registry |
| Botnet C2 IPs | abuse.ch Feodo Tracker | abuse.ch terms |
| Compromised hosts | Proofpoint Emerging Threats | ET open rules terms |
| Hijacked netblocks | Spamhaus DROP | Spamhaus DROP terms |
| Aggregated bad IPs | FireHOL level1 | per upstream lists |
| Scanner IPs | CINS Army | CINS terms |
| Tor exits | The Tor Project | public |
| Malicious domains (sensor) | HaGeZi Threat Intelligence Feeds (mini) | GPL-3.0 (used as data, not bundled) |
| Exposure | Shodan InternetDB | free for non-commercial use |
