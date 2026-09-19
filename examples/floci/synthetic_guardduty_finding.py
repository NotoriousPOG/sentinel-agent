"""Synthetic GuardDuty finding for the local Floci demo.

This object is not a finding from an AWS account. The title and description
say so. Addresses are from the RFC 5737 documentation ranges.

Field names are the GetFindings ``Finding`` object (camelCase), not the
AWS CLI's PascalCase output:

https://docs.aws.amazon.com/guardduty/latest/APIReference/API_Finding.html
https://docs.aws.amazon.com/guardduty/latest/APIReference/API_GetFindings.html

``schemaVersion`` ``2.0``, ``serviceName`` ``guardduty``, ``resourceRole``
``TARGET``, and account ``111122223333`` are values in the documented
``get-findings`` example:

https://docs.aws.amazon.com/cli/latest/reference/guardduty/get-findings.html

The finding type is named in the finding-format page. Severity ``2`` is
inside the documented low band (1.0–3.9). Nested members used below are
``Resource.instanceDetails``, ``NetworkInterface``, ``Service.action``,
``PortProbeAction``, ``PortProbeDetail``, ``RemoteIpDetails``, and
``LocalIpDetails`` on the Finding API pages linked from GetFindings.

https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-format.html
https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings-severity.html
https://docs.aws.amazon.com/guardduty/latest/APIReference/API_PortProbeAction.html
https://docs.aws.amazon.com/guardduty/latest/APIReference/API_PortProbeDetail.html
"""

import copy
from typing import Any

FINDING_DOC_URL = "https://docs.aws.amazon.com/guardduty/latest/APIReference/API_Finding.html"

# Placeholder detector id from the get-findings CLI example, not a live detector.
_EXAMPLE_DETECTOR = "12abc34d567e8fa901bc2d34eexample"
_ACCOUNT = "111122223333"
_FINDING_ID = "synthetic-guardduty-portprobe-203-0-113-50"

SYNTHETIC_GUARDDUTY_FINDING: dict[str, Any] = {
    "schemaVersion": "2.0",
    "accountId": _ACCOUNT,
    "region": "us-east-1",
    "partition": "aws",
    "id": _FINDING_ID,
    "arn": (
        f"arn:aws:guardduty:us-east-1:{_ACCOUNT}:detector/{_EXAMPLE_DETECTOR}/finding/{_FINDING_ID}"
    ),
    "type": "Recon:EC2/PortProbeUnprotectedPort",
    "severity": 2,
    "createdAt": "2026-09-19T03:45:00Z",
    "updatedAt": "2026-09-19T03:45:00Z",
    "title": "Synthetic: unprotected port probe against a documentation address.",
    "description": (
        "Synthetic fixture for a local demo. Not a finding from an AWS account. "
        "203.0.113.50 and 192.0.2.10 are documentation addresses from RFC 5737. "
        f"Field names follow {FINDING_DOC_URL}."
    ),
    "resource": {
        "instanceDetails": {
            "instanceId": "i-synthetic00000000001",
            "networkInterfaces": [
                {
                    "networkInterfaceId": "eni-synthetic00000000001",
                    "privateDnsName": "ip-192-0-2-10.ec2.internal",
                    "privateIpAddress": "192.0.2.10",
                    "publicIp": "198.51.100.20",
                }
            ],
        }
    },
    "service": {
        "serviceName": "guardduty",
        "detectorId": _EXAMPLE_DETECTOR,
        "resourceRole": "TARGET",
        "archived": False,
        "count": 1,
        "eventFirstSeen": "2026-09-19T03:45:00Z",
        "eventLastSeen": "2026-09-19T03:45:00Z",
        "action": {
            "actionType": "PORT_PROBE",
            "portProbeAction": {
                "blocked": False,
                "portProbeDetails": [
                    {
                        "localPortDetails": {"port": 22},
                        "localIpDetails": {"ipAddressV4": "192.0.2.10"},
                        "remoteIpDetails": {"ipAddressV4": "203.0.113.50"},
                    }
                ],
            },
        },
    },
}


def synthetic_guardduty_finding() -> dict[str, Any]:
    """Return a copy. Callers may delete fields without changing the constant."""
    return copy.deepcopy(SYNTHETIC_GUARDDUTY_FINDING)
