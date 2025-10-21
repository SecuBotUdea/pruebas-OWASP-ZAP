#!/usr/bin/env python3
"""
Normalizador de reportes OWASP ZAP
Lee el artifact generado y crea un reporte normalizado
"""

import json
import os
from datetime import datetime
from pathlib import Path


def load_zap_report(filepath='report_json.json'):
    """Carga el reporte JSON de OWASP ZAP"""
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)


def normalize_alert(alert):
    """Normaliza un alert individual de ZAP al formato estándar"""
    return {
        'id': alert.get('pluginid'),
        'name': alert.get('alert'),
        'severity': alert.get('risk', 'Unknown').upper(),
        'confidence': alert.get('confidence', 'Unknown'),
        'description': alert.get('desc', ''),
        'solution': alert.get('solution', ''),
        'references': alert.get('reference', '').split('\n') if alert.get('reference') else [],
        'cwe_id': alert.get('cweid'),
        'wasc_id': alert.get('wascid'),
        'instances': [
            {
                'url': instance.get('uri'),
                'method': instance.get('method'),
                'param': instance.get('param', ''),
                'attack': instance.get('attack', ''),
                'evidence': instance.get('evidence', '')
            }
            for instance in alert.get('instances', [])
        ],
        'count': len(alert.get('instances', []))
    }


def calculate_statistics(alerts):
    """Calcula estadísticas del reporte"""
    stats = {
        'total_alerts': len(alerts),
        'by_severity': {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFORMATIONAL': 0},
        'total_instances': 0
    }
    
    for alert in alerts:
        severity = alert['severity']
        stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1
        stats['total_instances'] += alert['count']
    
    return stats


def normalize_zap_report(zap_data):
    """
    Convierte el reporte ZAP a un formato normalizado
    """
    site = zap_data.get('site', [{}])[0]
    alerts = site.get('alerts', [])
    
    normalized_alerts = [normalize_alert(alert) for alert in alerts]
    stats = calculate_statistics(normalized_alerts)
    
    normalized_report = {
        'metadata': {
            'tool': 'OWASP ZAP',
            'scan_date': datetime.now().isoformat(),
            'target': site.get('@name', 'Unknown'),
            'report_version': '1.0'
        },
        'statistics': stats,
        'alerts': normalized_alerts
    }
    
    return normalized_report


def save_normalized_report(data, output_path='normalized_report.json'):
    """Guarda el reporte normalizado"""
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"Reporte normalizado guardado en: {output_path}")


def print_summary(stats):
    """Imprime un resumen del reporte"""
    print("\n" + "="*50)
    print("RESUMEN DEL REPORTE DE SEGURIDAD")
    print("="*50)
    print(f"Total de alertas: {stats['total_alerts']}")
    print(f"Total de instancias: {stats['total_instances']}")
    print("\nPor severidad:")
    for severity, count in stats['by_severity'].items():
        if count > 0:
            print(f"  • {severity}: {count}")
    print("="*50 + "\n")


def main():
    """Función principal"""
    try:
        # Verificar que existe el archivo
        if not Path('report_json.json').exists():
            print("Error: No se encontró report_json.json")
            return 1
        
        print("Cargando reporte de OWASP ZAP...")
        zap_data = load_zap_report()
        
        print("Normalizando datos...")
        normalized = normalize_zap_report(zap_data)
        
        print("Guardando reporte normalizado...")
        save_normalized_report(normalized)
        
        print_summary(normalized['statistics'])
        
        return 0
        
    except Exception as e:
        print(f"Error al procesar el reporte: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    exit(main())