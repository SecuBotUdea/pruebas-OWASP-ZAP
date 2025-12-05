#!/usr/bin/env python3
"""
Normalizador de reportes OWASP ZAP
Lee el artifact generado y crea un reporte normalizado con:
- Lista completa de alertas detectadas
- Severidad (High, Medium, Low, Informational)
- Descripción de cada vulnerabilidad
- Evidencia encontrada
- Recomendaciones de remediación
"""

import json
import os
from datetime import datetime
from pathlib import Path
import html


def load_zap_report(filepath='report_json.json'):
    """Carga el reporte JSON de OWASP ZAP"""
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)


def extract_evidence(instances):
    """Extrae y formatea la evidencia de las instancias"""
    evidence_list = []
    
    for instance in instances:
        evidence = {
            'url': instance.get('uri', 'N/A'),
            'method': instance.get('method', 'N/A'),
            'parameter': instance.get('param', 'N/A'),
            'attack_vector': instance.get('attack', 'N/A'),
            'evidence_raw': instance.get('evidence', 'N/A')
        }
        
        # Solo incluir instancias con evidencia relevante
        if (evidence['evidence_raw'] not in ['N/A', '', None] or 
            evidence['attack_vector'] not in ['N/A', '', None]):
            evidence_list.append(evidence)
    
    return evidence_list


def normalize_alert(alert):
    """Normaliza un alert individual de ZAP al formato estándar"""
    # Mapeo de severidad ZAP a formato estándar
    risk_mapping = {
        '3': 'HIGH',
        'High': 'HIGH',
        'high': 'HIGH',
        '2': 'MEDIUM',
        'Medium': 'MEDIUM',
        'medium': 'MEDIUM',
        '1': 'LOW',
        'Low': 'LOW',
        'low': 'LOW',
        '0': 'INFORMATIONAL',
        'Informational': 'INFORMATIONAL',
        'informational': 'INFORMATIONAL'
    }
    
    risk_code = alert.get('riskcode', '0')
    risk_desc = alert.get('riskdesc', 'Informational')
    
    # Determinar severidad
    severity = risk_mapping.get(risk_code, 
                               risk_mapping.get(risk_desc, 'INFORMATIONAL'))
    
    # Extraer evidencias
    instances = alert.get('instances', [])
    evidences = extract_evidence(instances)
    
    # Limpiar HTML de la descripción y solución
    description = html.unescape(alert.get('desc', '')).strip()
    solution = html.unescape(alert.get('solution', '')).strip()
    
    # Formatear referencias
    references = []
    if alert.get('reference'):
        ref_text = alert.get('reference', '')
        # Separar por líneas y filtrar vacías
        ref_lines = [line.strip() for line in ref_text.split('\n') if line.strip()]
        references = ref_lines
    
    return {
        'id': alert.get('pluginid', 'N/A'),
        'name': alert.get('alert', 'Unknown Alert'),
        'severity': severity,
        'confidence': alert.get('confidence', 'Unknown'),
        'description': description,
        'solution': solution,  # Recomendaciones de remediación
        'references': references,
        'cwe_id': alert.get('cweid', 'N/A'),
        'wasc_id': alert.get('wascid', 'N/A'),
        'evidence_count': len(evidences),
        'evidences': evidences,  # Evidencia encontrada
        'instances': [
            {
                'url': instance.get('uri', 'N/A'),
                'method': instance.get('method', 'N/A'),
                'parameter': instance.get('param', 'N/A'),
                'attack': instance.get('attack', 'N/A')
            }
            for instance in instances[:5]  # Limitar a 5 instancias para mantener el tamaño manejable
        ],
        'count': len(instances)
    }


def calculate_statistics(alerts):
    """Calcula estadísticas detalladas del reporte"""
    stats = {
        'total_alerts': len(alerts),
        'by_severity': {
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFORMATIONAL': 0
        },
        'by_confidence': {
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'None': 0
        },
        'total_instances': 0,
        'vulnerability_distribution': {}
    }
    
    for alert in alerts:
        severity = alert['severity']
        confidence = alert.get('confidence', 'None')
        
        # Contar por severidad
        stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1
        
        # Contar por confianza
        if confidence in stats['by_confidence']:
            stats['by_confidence'][confidence] += 1
        
        # Contar total de instancias
        stats['total_instances'] += alert['count']
        
        # Distribución por tipo de vulnerabilidad
        vuln_name = alert['name']
        stats['vulnerability_distribution'][vuln_name] = stats['vulnerability_distribution'].get(vuln_name, 0) + 1
    
    return stats


def normalize_zap_report(zap_data):
    """
    Convierte el reporte ZAP a un formato normalizado completo
    """
    sites = zap_data.get('site', [])
    
    all_alerts = []
    target_urls = []
    
    # Procesar todos los sitios
    for site in sites:
        site_name = site.get('@name', 'Unknown')
        if site_name not in target_urls:
            target_urls.append(site_name)
        
        alerts = site.get('alerts', [])
        for alert in alerts:
            normalized_alert = normalize_alert(alert)
            all_alerts.append(normalized_alert)
    
    # Ordenar alertas por severidad (HIGH primero)
    severity_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2, 'INFORMATIONAL': 3}
    all_alerts.sort(key=lambda x: severity_order.get(x['severity'], 4))
    
    # Calcular estadísticas
    stats = calculate_statistics(all_alerts)
    
    # Crear reporte normalizado completo
    normalized_report = {
        'metadata': {
            'tool': 'OWASP ZAP',
            'scan_date': datetime.now().isoformat(),
            'report_generated': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'targets': target_urls,
            'zap_version': zap_data.get('@version', 'Unknown'),
            'report_version': '2.0',
            'scan_duration': 'N/A'  # ZAP no siempre proporciona esta información
        },
        'summary': {
            'total_vulnerabilities': stats['total_alerts'],
            'total_instances': stats['total_instances'],
            'by_severity': stats['by_severity'],
            'by_confidence': stats['by_confidence'],
            'top_vulnerabilities': dict(sorted(
                stats['vulnerability_distribution'].items(),
                key=lambda x: x[1],
                reverse=True
            )[:10])  # Top 10 vulnerabilidades más comunes
        },
        'detailed_findings': {
            'high_risk': [alert for alert in all_alerts if alert['severity'] == 'HIGH'],
            'medium_risk': [alert for alert in all_alerts if alert['severity'] == 'MEDIUM'],
            'low_risk': [alert for alert in all_alerts if alert['severity'] == 'LOW'],
            'informational': [alert for alert in all_alerts if alert['severity'] == 'INFORMATIONAL']
        },
        'remediation_guidance': {
            'high_priority': 'Las vulnerabilidades de alto riesgo deben ser abordadas inmediatamente.',
            'medium_priority': 'Las vulnerabilidades de riesgo medio deben ser planificadas para su resolución.',
            'low_priority': 'Las vulnerabilidades de bajo riesgo pueden ser consideradas en futuras actualizaciones.',
            'general_recommendations': [
                'Implementar WAF (Web Application Firewall)',
                'Realizar pruebas de penetración periódicas',
                'Mantener actualizados todos los componentes',
                'Implementar políticas de seguridad de headers HTTP',
                'Configurar CSP (Content Security Policy) adecuadamente'
            ]
        },
        'all_alerts': all_alerts  # Lista completa de alertas
    }
    
    return normalized_report


def save_normalized_report(data, output_path='normalized_report.json'):
    """Guarda el reporte normalizado"""
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"✅ Reporte normalizado guardado en: {output_path}")


def print_detailed_summary(stats, all_alerts):
    """Imprime un resumen detallado del reporte"""
    print("\n" + "="*60)
    print("REPORTE DETALLADO DE VULNERABILIDADES - OWASP ZAP")
    print("="*60)
    
    print(f"\n📊 ESTADÍSTICAS GENERALES:")
    print(f"   • Total de alertas: {stats['total_alerts']}")
    print(f"   • Total de instancias: {stats['total_instances']}")
    
    print(f"\n📈 DISTRIBUCIÓN POR SEVERIDAD:")
    for severity, count in stats['by_severity'].items():
        if count > 0:
            print(f"   • {severity}: {count}")
    
    print(f"\n🔍 DISTRIBUCIÓN POR CONFIANZA:")
    for confidence, count in stats['by_confidence'].items():
        if count > 0:
            print(f"   • {confidence}: {count}")
    
    print(f"\n🎯 TOP 5 VULNERABILIDADES MÁS COMUNES:")
    top_vulns = sorted(stats['vulnerability_distribution'].items(), 
                      key=lambda x: x[1], reverse=True)[:5]
    for i, (vuln_name, count) in enumerate(top_vulns, 1):
        print(f"   {i}. {vuln_name}: {count} ocurrencias")
    
    print(f"\n📋 LISTA COMPLETA DE ALERTAS:")
    print("   " + "-"*50)
    for i, alert in enumerate(all_alerts[:20], 1):  # Mostrar primeras 20 alertas
        print(f"   {i}. [{alert['severity']}] {alert['name']}")
        print(f"      Descripción: {alert['description'][:100]}...")
        print(f"      Instancias: {alert['count']}")
        print(f"      Evidencias: {alert['evidence_count']}")
        print()
    
    if len(all_alerts) > 20:
        print(f"   ... y {len(all_alerts) - 20} alertas más")
    
    print("="*60 + "\n")


def main():
    """Función principal"""
    try:
        # Verificar que existe el archivo
        if not Path('report_json.json').exists():
            print("❌ Error: No se encontró report_json.json")
            print("   Asegúrate de que el escaneo ZAP se haya completado.")
            return 1
        
        print("📥 Cargando reporte de OWASP ZAP...")
        zap_data = load_zap_report()
        
        print("🔄 Normalizando datos...")
        normalized = normalize_zap_report(zap_data)
        
        print("💾 Guardando reporte normalizado...")
        save_normalized_report(normalized)
        
        # Imprimir resumen detallado
        print_detailed_summary(normalized['summary'], normalized['all_alerts'])
        
        # Generar también un resumen ejecutivo en formato texto
        generate_executive_summary(normalized)
        
        return 0
        
    except json.JSONDecodeError as e:
        print(f"❌ Error: El archivo JSON está mal formado: {e}")
        return 1
    except Exception as e:
        print(f"❌ Error al procesar el reporte: {e}")
        import traceback
        traceback.print_exc()
        return 1


def generate_executive_summary(normalized_report):
    """Genera un resumen ejecutivo en formato texto"""
    summary_file = 'zap_executive_summary.txt'
    
    with open(summary_file, 'w', encoding='utf-8') as f:
        f.write("="*70 + "\n")
        f.write("RESUMEN EJECUTIVO - ESCANEO DE SEGURIDAD OWASP ZAP\n")
        f.write("="*70 + "\n\n")
        
        f.write("INFORMACIÓN DEL ESCANEO:\n")
        f.write(f"• Fecha: {normalized_report['metadata']['report_generated']}\n")
        f.write(f"• Herramienta: {normalized_report['metadata']['tool']}\n")
        f.write(f"• Versión ZAP: {normalized_report['metadata']['zap_version']}\n")
        f.write(f"• Objetivos: {', '.join(normalized_report['metadata']['targets'])}\n\n")
        
        f.write("RESULTADOS PRINCIPALES:\n")
        summary = normalized_report['summary']
        f.write(f"• Total de vulnerabilidades: {summary['total_vulnerabilities']}\n")
        f.write(f"• Total de instancias encontradas: {summary['total_instances']}\n\n")
        
        f.write("DISTRIBUCIÓN POR RIESGO:\n")
        for severity, count in summary['by_severity'].items():
            if count > 0:
                f.write(f"  • {severity}: {count} vulnerabilidades\n")
        
        f.write("\nVULNERABILIDADES MÁS CRÍTICAS:\n")
        high_risk = normalized_report['detailed_findings']['high_risk']
        for i, vuln in enumerate(high_risk[:5], 1):
            f.write(f"{i}. {vuln['name']}\n")
            f.write(f"   Descripción: {vuln['description'][:150]}...\n")
            f.write(f"   Evidencias: {vuln['evidence_count']} encontradas\n")
            f.write(f"   Recomendación: {vuln['solution'][:200]}...\n\n")
        
        f.write("RECOMENDACIONES GENERALES:\n")
        for i, rec in enumerate(normalized_report['remediation_guidance']['general_recommendations'], 1):
            f.write(f"{i}. {rec}\n")
        
        f.write("\n" + "="*70 + "\n")
        f.write("Reporte generado automáticamente por el normalizador OWASP ZAP\n")
        f.write("="*70 + "\n")
    
    print(f"📄 Resumen ejecutivo generado: {summary_file}")


if __name__ == '__main__':
    exit(main())
