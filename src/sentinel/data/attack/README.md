# Enterprise ATT&CK catalog

This directory is a checked-in extract of official MITRE ATT&CK technique records.
Tests read it from disk. Nothing in the test suite downloads it.

| | |
| --- | --- |
| Source | https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-19.2.json |
| Repository | https://github.com/mitre-attack/attack-stix-data |
| Release | https://github.com/mitre-attack/attack-stix-data/releases/tag/v19.2 |
| ATT&CK version | 19.2 (Enterprise collection `modified` 2026-08-05T21:33:58.496Z, ATT&CK spec 3.3.0) |
| Retrieved | 2026-09-22 |

`enterprise-techniques.json` holds every non-revoked, non-deprecated `attack-pattern` from that STIX 2.1 bundle. Names, descriptions, and tactic names are copied from the bundle. Tactic short names were resolved through the bundle's `x-mitre-tactic` objects. Techniques with more than one tactic keep those official names in kill-chain order.

Revoked and deprecated patterns are omitted. A search miss means the technique is not in this extract. Descriptions are stored as text. URLs inside them are not fetched.
