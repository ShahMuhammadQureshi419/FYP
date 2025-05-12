# mobsf_json_parser.py

import json
from datetime import datetime

def extract_mobsf_summary(json_path):
    with open(json_path, 'r') as file:
        data = json.load(file)

    # Primary App Details
    app_name = data.get("app_name", "Unknown")
    app_type = data.get("app_type", "apk")
    file_name = data.get("file_name", "")
    hash_md5 = data.get("md5", "")

    # Static Info
    main_activity = data.get("main_activity", "")
    version_name = data.get("version_name", "Unknown")
    target_sdk = data.get("target_sdk", "Unknown")

    # Scan Date Handling
    scan_timestamp = data.get("timestamp", "")
    if scan_timestamp:
        formatted_scan_date = datetime.fromisoformat(scan_timestamp.replace("Z", "")).strftime("%b %d, %Y, %-I:%M %p")
    else:
        formatted_scan_date = "Unknown"

    # File Size & Hashes
    file_size = data.get("size", "0MB")
    sha1 = data.get("sha1", "")
    sha256 = data.get("sha256", "")

    # Security Score - Now properly extracted from root level
    app_sec = data.get("appsec",{})
    security_score = app_sec.get("security_score" , 0)

    # Tracker Detection
    tracker_data = data.get("trackers", {})
    total_trackers = tracker_data.get("total_trackers", 0)
    detected_trackers = tracker_data.get("detected_trackers", 0)
    tracker_details = tracker_data.get("trackers", [])

    trackers = [
        {
            "name": t.get("name"),
            "categories": t.get("categories"),
            "url": t.get("url")
        }
        for t in tracker_details if t.get("name")  # Only include if name exists
    ]

    # Permissions: Only Dangerous and Warning
    permissions = data.get("permissions", {})
    filtered_permissions = []
    for perm_name, perm_data in permissions.items():
        status = perm_data.get("status", "").lower()
        if status in ("dangerous", "warning"):
            filtered_permissions.append({
                "permission": perm_name,
                "status": status,
                "info": perm_data.get("info", ""),
                "description": perm_data.get("description", "")
            })

    # Permission counts
    malware_perms = data.get("malware_permissions", {})
    total_malware_permissions = malware_perms.get("total_malware_permissions", 0)
    total_other_permissions = malware_perms.get("total_other_permissions", 0)

    # Enhanced Severity Summary
    manifest_summary = data.get("manifest_summary", {})
    cert_summary = data.get("certificate_summary", {})
    code_summary = data.get("code_analysis", {}).get("summary", {})
    
    severity = {
        "high": (manifest_summary.get("high", 0) + 
                cert_summary.get("high", 0) +
                code_summary.get("high", 0)),
        "info": (manifest_summary.get("info", 0) + 
                cert_summary.get("info", 0) +
                code_summary.get("info", 0)),
        "secure": 1 if data.get("network_security", {}).get("network_findings") else 0,
        "warning": (manifest_summary.get("warning", 0) + 
                   cert_summary.get("warning", 0) +
                   code_summary.get("warning", 0)),
        "suppressed": manifest_summary.get("suppressed", 0)
    }

    return {
        "app_name": app_name,
        "app_type": app_type,
        "file_name": file_name,
        "hash": hash_md5,
        "main_activity": main_activity,
        "version_name": version_name,
        "target_sdk": target_sdk,
        "scan_date": formatted_scan_date,
        "file_size": file_size,
        "sha1": sha1,
        "sha256": sha256,
        "security_score": security_score,
        "trackers_detected": detected_trackers,
        "total_trackers": total_trackers,
        "trackers": trackers,
        "dangerous_and_warning_permissions": filtered_permissions,
        "total_malware_permissions": total_malware_permissions,
        "total_other_permissions": total_other_permissions,
        "severity_summary": severity
    }
