import json
import sys
from datetime import datetime

def convert_zap_to_sarif(zap_json_path, sarif_output_path):
    """Convert ZAP JSON report to SARIF format"""
    
    # Load ZAP JSON report
    with open(zap_json_path, 'r', encoding='utf-8') as f:
        zap_data = json.load(f)
    
    # Map ZAP risk levels to SARIF levels
    risk_to_level = {
        '3': 'error',      # High
        '2': 'warning',    # Medium
        '1': 'note',       # Low
        '0': 'note'        # Informational
    }
    
    # Initialize SARIF structure
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "OWASP ZAP",
                        "informationUri": "https://www.zaproxy.org/",
                        "version": zap_data.get('@version', 'unknown'),
                        "rules": []
                    }
                },
                "results": [],
                "properties": {
                    "generated": zap_data.get('@generated', datetime.utcnow().isoformat())
                }
            }
        ]
    }
    
    run = sarif['runs'][0]
    rules_dict = {}
    
    # Process alerts from all sites
    for site in zap_data.get('site', []):
        site_url = site.get('@name', 'unknown')
        
        for alert in site.get('alerts', []):
            risk_code = alert.get('riskcode', '0')
            alert_id = alert.get('pluginid', 'unknown')
            
            # Create rule if it doesn't exist
            if alert_id not in rules_dict:
                rule = {
                    "id": alert_id,
                    "name": alert.get('alert', 'Unknown Alert'),
                    "shortDescription": {
                        "text": alert.get('alert', 'Unknown Alert')
                    },
                    "fullDescription": {
                        "text": alert.get('desc', 'No description available')
                    },
                    "help": {
                        "text": alert.get('solution', 'No solution provided')
                    },
                    "properties": {
                        "tags": [
                            f"security",
                            f"risk-{alert.get('riskdesc', 'unknown').lower()}",
                            f"confidence-{alert.get('confidence', 'unknown').lower()}"
                        ]
                    }
                }
                
                if alert.get('reference'):
                    rule["helpUri"] = alert.get('reference').split('\n')[0].strip()
                
                run['tool']['driver']['rules'].append(rule)
                rules_dict[alert_id] = True
            
            # Process each instance of the alert
            for instance in alert.get('instances', []):
                result = {
                    "ruleId": alert_id,
                    "level": risk_to_level.get(risk_code, 'note'),
                    "message": {
                        "text": alert.get('alert', 'Unknown Alert')
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": instance.get('uri', site_url)
                                },
                                "region": {
                                    "snippet": {
                                        "text": instance.get('evidence', '')[:200]  # Limit evidence length
                                    }
                                }
                            }
                        }
                    ],
                    "properties": {
                        "method": instance.get('method', 'unknown'),
                        "param": instance.get('param', ''),
                        "attack": instance.get('attack', ''),
                        "cweid": alert.get('cweid', ''),
                        "wascid": alert.get('wascid', ''),
                        "risk": alert.get('riskdesc', ''),
                        "confidence": alert.get('confidence', '')
                    }
                }
                
                run['results'].append(result)
    
    # Write SARIF file
    with open(sarif_output_path, 'w', encoding='utf-8') as f:
        json.dump(sarif, f, indent=2)
    
    print(f"✓ SARIF report generated: {sarif_output_path}")
    print(f"  Total rules: {len(run['tool']['driver']['rules'])}")
    print(f"  Total results: {len(run['results'])}")

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python convert_zap_to_sarif.py <zap_json_file> <sarif_output_file>")
        sys.exit(1)
    
    zap_json_path = sys.argv[1]
    sarif_output_path = sys.argv[2]
    
    convert_zap_to_sarif(zap_json_path, sarif_output_path)
