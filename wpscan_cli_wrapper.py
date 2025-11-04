#!/usr/bin/env python3
"""
WPScan CLI Wrapper - Plugin Security Report (FIXED)
Wraps the WPScan command-line tool for easier multi-site scanning with focus on plugin vulnerabilities
"""

import subprocess
import json
import argparse
import sys
import os
from datetime import datetime
from typing import List, Dict, Any
import concurrent.futures


def get_severity(vuln_title: str) -> tuple:
    """Determine severity from vulnerability title"""
    title_lower = vuln_title.lower()
    
    if any(word in title_lower for word in ['sqli', 'sql injection', 'remote code execution', 'rce', 'authentication bypass']):
        return ('critical', 'CRITICAL')
    if any(word in title_lower for word in ['csrf', 'cross-site request forgery', 'privilege escalation', 'ssrf']):
        return ('high', 'HIGH')
    if any(word in title_lower for word in ['xss', 'cross-site scripting', 'information disclosure', 'sensitive information']):
        return ('medium', 'MEDIUM')
    if any(word in title_lower for word in ['missing authorization']):
        return ('low', 'LOW')
    
    return ('medium', 'MEDIUM')


class WPScanCLI:
    """Wrapper for WPScan CLI tool"""
    
    def __init__(self, api_token: str):
        """
        Initialize the WPScan CLI wrapper
        
        Args:
            api_token: Your WPScan API token
        """
        self.api_token = api_token
        self.wpscan_path = self.find_wpscan()
        self.check_wpscan_installed()
    
    def find_wpscan(self):
        """Find WPScan installation path"""
        # Common installation paths
        paths = [
            '/opt/homebrew/bin/wpscan',  # Homebrew on Apple Silicon
            '/usr/local/bin/wpscan',      # Homebrew on Intel Mac
            'wpscan'                       # System PATH
        ]
        
        for path in paths:
            try:
                result = subprocess.run([path, '--version'], 
                                      capture_output=True, 
                                      text=True, 
                                      timeout=5)
                if result.returncode == 0:
                    return path
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
        
        return 'wpscan'  # Fallback to default
    
    def check_wpscan_installed(self):
        """Check if WPScan CLI is installed"""
        try:
            result = subprocess.run([self.wpscan_path, '--version'], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=5)
            if result.returncode != 0:
                raise FileNotFoundError
        except (FileNotFoundError, subprocess.TimeoutExpired):
            print("❌ ERROR: WPScan is not installed!")
            print("\n📦 To install WPScan:")
            print("   brew install wpscan")
            print("\n   Or visit: https://github.com/wpscanteam/wpscan")
            sys.exit(1)
    
    def scan_site(self, url: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Scan a WordPress site using WPScan CLI
        
        Args:
            url: The WordPress site URL to scan
            options: Additional scanning options
            
        Returns:
            Dictionary containing scan results
        """
        # Ensure URL has protocol
        if not url.startswith(('http://', 'https://')):
            url = f'https://{url}'
        
        # Build command
        cmd = [
            self.wpscan_path,
            '--url', url,
            '--api-token', self.api_token,
            '--format', 'json',
            '--random-user-agent'
        ]
        
        # Add optional parameters
        if options:
            if options.get('enumerate'):
                cmd.extend(['--enumerate', options['enumerate']])
            if options.get('plugins_detection'):
                cmd.extend(['--plugins-detection', options['plugins_detection']])
            if options.get('detection_mode'):
                cmd.extend(['--detection-mode', options['detection_mode']])
            if options.get('disable_tls_checks'):
                cmd.append('--disable-tls-checks')
        
        print(f"🔍 Scanning: {url}")
        
        try:
            # Run WPScan
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            # Parse JSON output
            try:
                scan_data = json.loads(result.stdout)
                return {
                    'url': url,
                    'status': 'success',
                    'data': scan_data
                }
            except json.JSONDecodeError:
                return {
                    'url': url,
                    'status': 'error',
                    'error': 'Failed to parse scan results',
                    'output': result.stdout[:500]
                }
                
        except subprocess.TimeoutExpired:
            return {
                'url': url,
                'status': 'error',
                'error': 'Scan timed out after 5 minutes'
            }
        except Exception as e:
            return {
                'url': url,
                'status': 'error',
                'error': str(e)
            }


def print_plugin_report(result: Dict[str, Any]):
    """Print formatted plugin security report"""
    print(f"\n{'='*100}")
    print(f"🌐 Site: {result['url']}")
    print(f"{'='*100}")
    
    if result['status'] == 'error':
        print(f"❌ Error: {result['error']}")
        if 'output' in result:
            print(f"\nOutput:\n{result['output']}")
        return
    
    data = result['data']
    
    # WordPress Version
    if 'version' in data:
        version_info = data['version']
        if version_info and isinstance(version_info, dict):
            wp_version = version_info.get('number', 'Unknown')
            wp_status = version_info.get('status', 'unknown')
            wp_vulns = len(version_info.get('vulnerabilities', []))
            
            print(f"\n📦 WordPress Core")
            print(f"   Version: {wp_version}")
            print(f"   Status: {'❌ FAIL' if wp_status == 'insecure' or wp_vulns > 0 else '✅ PASS'}")
            if wp_vulns > 0:
                print(f"   Vulnerabilities: {wp_vulns}")
    
    # Plugins
    if 'plugins' in data and data['plugins']:
        print(f"\n{'='*100}")
        print(f"🔌 PLUGINS REPORT ({len(data['plugins'])} plugins found)")
        print(f"{'='*100}")
        print(f"\n{'Plugin Name':<40} {'Version':<15} {'Status':<18} {'Vulnerabilities'}")
        print(f"{'-'*40} {'-'*15} {'-'*18} {'-'*30}")
        
        plugins_list = []
        for slug, plugin_data in data['plugins'].items():
            # FIXED: Handle case where version might be None
            version_data = plugin_data.get('version')
            version_detected = version_data and isinstance(version_data, dict)
            if version_detected:
                version = version_data.get('number', 'Unknown')
            else:
                version = 'Not Detected'
            
            vulns = plugin_data.get('vulnerabilities', [])
            vuln_count = len(vulns)
            
            # Determine if vulnerabilities affect this version
            if vuln_count > 0:
                if version_detected and version != 'Unknown':
                    # Check if current version is vulnerable
                    is_vulnerable = False
                    for vuln in vulns:
                        fixed_in = vuln.get('fixed_in')
                        if fixed_in:
                            try:
                                # Simple version comparison (works for most cases)
                                if version < fixed_in:
                                    is_vulnerable = True
                                    break
                            except:
                                is_vulnerable = True  # Can't compare, assume vulnerable
                        else:
                            is_vulnerable = True  # No fix version, assume vulnerable
                    
                    if is_vulnerable:
                        status = '❌ VULNERABLE'
                        vuln_text = f"{vuln_count} CONFIRMED"
                    else:
                        status = '✅ PASS'
                        vuln_text = "Fixed"
                else:
                    # Version unknown - potential risk
                    status = '⚠️  UNKNOWN'
                    vuln_text = f"{vuln_count} POSSIBLE (check manually)"
            else:
                status = '✅ PASS'
                vuln_text = "None"
            
            plugins_list.append({
                'slug': slug,
                'version': version,
                'version_detected': version_detected,
                'status': status,
                'vuln_count': vuln_count,
                'vulns': vulns
            })
            
            print(f"{slug:<40} {version:<15} {status:<18} {vuln_text}")
        
        # Detailed vulnerability information
        vulnerable_plugins = [p for p in plugins_list if p['vuln_count'] > 0]
        if vulnerable_plugins:
            print(f"\n{'='*100}")
            print(f"⚠️  VULNERABILITY DETAILS")
            print(f"{'='*100}")
            
            for plugin in vulnerable_plugins:
                version_status = "✅ Detected" if plugin['version_detected'] else "⚠️  NOT DETECTED"
                print(f"\n🔴 {plugin['slug']} (v{plugin['version']}) - {plugin['vuln_count']} vulnerabilities")
                print(f"    Version Status: {version_status}")
                if not plugin['version_detected']:
                    print(f"    ⚠️  ACTION REQUIRED: Version could not be detected. Manually check WordPress admin")
                    print(f"        to verify your version is >= the fixed versions listed below.")
                print(f"{'-'*100}")
                
                for i, vuln in enumerate(plugin['vulns'], 1):
                    print(f"\n   [{i}] {vuln.get('title', 'Unknown vulnerability')}")
                    if vuln.get('vuln_type'):
                        print(f"       Type: {vuln['vuln_type']}")
                    if vuln.get('fixed_in'):
                        print(f"       ✅ Fixed in version: {vuln['fixed_in']}")
                    else:
                        print(f"       ⚠️  No fix available yet")
                    
                    if vuln.get('references'):
                        refs = vuln['references']
                        if refs.get('cve'):
                            print(f"       CVE: {', '.join(refs['cve'][:3])}")
                        if refs.get('url'):
                            print(f"       URL: {refs['url'][0] if refs['url'] else 'N/A'}")
    else:
        print(f"\n🔌 Plugins: No plugins detected (or detection disabled)")
    
    # Theme
    if 'main_theme' in data:
        theme = data['main_theme']
        theme_slug = theme.get('slug', 'Unknown')
        
        # FIXED: Handle case where theme version might be None
        theme_version_data = theme.get('version')
        if theme_version_data and isinstance(theme_version_data, dict):
            theme_version = theme_version_data.get('number', 'Unknown')
        else:
            theme_version = 'Unknown'
        
        theme_vulns = theme.get('vulnerabilities', [])
        theme_status = '❌ FAIL' if len(theme_vulns) > 0 else '✅ PASS'
        
        print(f"\n{'='*100}")
        print(f"🎨 THEME")
        print(f"{'='*100}")
        print(f"   Name: {theme_slug}")
        print(f"   Version: {theme_version}")
        print(f"   Status: {theme_status}")
        if theme_vulns:
            print(f"   Vulnerabilities: {len(theme_vulns)}")


def generate_html_report(results: List[Dict[str, Any]]) -> str:
    """Generate an HTML report from scan results"""
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WPScan Security Report - {datetime.now().strftime('%Y-%m-%d')}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; margin: 0; padding: 20px; line-height: 1.6; }}
        .container {{ max-width: 1400px; margin: 0 auto; background: white; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
        .header h1 {{ margin: 0 0 10px 0; font-size: 2.5em; }}
        .summary {{ background: #f8f9fa; padding: 30px; border-bottom: 2px solid #e9ecef; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }}
        .summary-card {{ background: white; padding: 20px; border-radius: 8px; text-align: center; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        .summary-number {{ font-size: 2.5em; font-weight: bold; color: #667eea; }}
        .summary-label {{ color: #666; margin-top: 5px; }}
        .site-section {{ padding: 30px; border-bottom: 2px solid #e9ecef; }}
        .site-section:last-child {{ border-bottom: none; }}
        .site-header {{ margin-bottom: 20px; }}
        .site-url {{ font-size: 1.5em; font-weight: 600; color: #333; margin-bottom: 10px; }}
        .badge {{ display: inline-block; padding: 6px 12px; border-radius: 20px; font-size: 0.85em; font-weight: 600; margin: 5px 5px 5px 0; }}
        .badge-success {{ background: #d4edda; color: #155724; }}
        .badge-warning {{ background: #fff3cd; color: #856404; }}
        .badge-danger {{ background: #f8d7da; color: #721c24; }}
        .info-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
        .info-card {{ background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #667eea; }}
        .info-label {{ font-size: 0.85em; color: #666; margin-bottom: 5px; }}
        .info-value {{ font-weight: 600; font-size: 1.1em; color: #333; }}
        .plugin-table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        .plugin-table th {{ background: #667eea; color: white; padding: 12px; text-align: left; }}
        .plugin-table td {{ padding: 12px; border-bottom: 1px solid #e9ecef; }}
        .plugin-table tr:hover {{ background: #f8f9fa; }}
        .vuln-details {{ background: #fff5f5; border-left: 4px solid #dc3545; padding: 15px; margin: 10px 0; border-radius: 5px; }}
        .vuln-details.critical {{ background: #fee; border-left-color: #8b0000; }}
        .vuln-details.high {{ background: #fff5f5; border-left-color: #dc3545; }}
        .vuln-details.medium {{ background: #fff8e1; border-left-color: #ff9800; }}
        .vuln-details.low {{ background: #f1f8ff; border-left-color: #2196f3; }}
        .vuln-title {{ font-weight: 600; color: #721c24; margin-bottom: 8px; }}
        .vuln-meta {{ font-size: 0.9em; color: #666; }}
        .severity-badge {{ display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 0.75em; font-weight: 700; text-transform: uppercase; margin-left: 10px; }}
        .severity-critical {{ background: #8b0000; color: white; }}
        .severity-high {{ background: #dc3545; color: white; }}
        .severity-medium {{ background: #ff9800; color: white; }}
        .severity-low {{ background: #2196f3; color: white; }}
        .error-box {{ background: #f8d7da; border-left: 4px solid #dc3545; padding: 15px; border-radius: 5px; color: #721c24; }}
        .warning-box {{ background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; border-radius: 5px; color: #856404; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 WPScan Security Report</h1>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
"""
    
    # Calculate summary stats
    total = len(results)
    successful = sum(1 for r in results if r['status'] == 'success')
    errors = total - successful
    total_plugins = 0
    vulnerable_plugins = 0
    total_vulns = 0
    
    for result in results:
        if result['status'] == 'success':
            data = result['data']
            if 'plugins' in data:
                total_plugins += len(data['plugins'])
                for plugin_data in data['plugins'].values():
                    vulns = plugin_data.get('vulnerabilities', [])
                    if vulns:
                        vulnerable_plugins += 1
                        total_vulns += len(vulns)
            if 'main_theme' in data:
                total_vulns += len(data['main_theme'].get('vulnerabilities', []))
            if 'version' in data:
                total_vulns += len(data['version'].get('vulnerabilities', []))
    
    # Summary section
    html += """
        <div class="summary">
            <div class="summary-grid">
                <div class="summary-card">
                    <div class="summary-number">{}</div>
                    <div class="summary-label">Sites Scanned</div>
                </div>
                <div class="summary-card">
                    <div class="summary-number">{}</div>
                    <div class="summary-label">Total Plugins</div>
                </div>
                <div class="summary-card">
                    <div class="summary-number">{}</div>
                    <div class="summary-label">Vulnerable Plugins</div>
                </div>
                <div class="summary-card">
                    <div class="summary-number">{}</div>
                    <div class="summary-label">Total Vulnerabilities</div>
                </div>
            </div>
        </div>
    """.format(successful, total_plugins, vulnerable_plugins, total_vulns)
    
    # Individual site sections
    for result in results:
        url = result['url']
        html += f'<div class="site-section"><div class="site-header"><div class="site-url">{url}</div>'
        
        if result['status'] == 'error':
            html += f'<div class="error-box"><strong>Error:</strong> {result.get("error", "Unknown error")}</div></div></div>'
            continue
        
        data = result['data']
        
        # Count site vulnerabilities
        site_vulns = 0
        if 'plugins' in data:
            for plugin_data in data['plugins'].values():
                site_vulns += len(plugin_data.get('vulnerabilities', []))
        if 'main_theme' in data:
            site_vulns += len(data['main_theme'].get('vulnerabilities', []))
        if 'version' in data:
            site_vulns += len(data['version'].get('vulnerabilities', []))
        
        # Status badge
        if site_vulns == 0:
            html += '<span class="badge badge-success">✅ No Vulnerabilities</span>'
        else:
            html += f'<span class="badge badge-danger">⚠️ {site_vulns} Vulnerabilities</span>'
        
        html += '</div>'
        
        # WordPress info
        html += '<div class="info-grid">'
        if 'version' in data:
            wp_version = data['version'].get('number', 'Unknown')
            wp_status = data['version'].get('status', 'unknown')
            status_text = '⚠️ Insecure' if wp_status == 'insecure' else '✅ Secure'
            html += f'<div class="info-card"><div class="info-label">WordPress Version</div><div class="info-value">{wp_version} {status_text}</div></div>'
        
        if 'main_theme' in data:
            theme = data['main_theme']
            theme_name = theme.get('slug', 'Unknown')
            theme_version_data = theme.get('version')
            if theme_version_data and isinstance(theme_version_data, dict):
                theme_version = theme_version_data.get('number', 'Unknown')
            else:
                theme_version = 'Unknown'
            html += f'<div class="info-card"><div class="info-label">Theme</div><div class="info-value">{theme_name} v{theme_version}</div></div>'
        
        if 'plugins' in data:
            plugin_count = len(data['plugins'])
            html += f'<div class="info-card"><div class="info-label">Plugins Detected</div><div class="info-value">{plugin_count}</div></div>'
        
        html += '</div>'
        
        # Plugins table
        if 'plugins' in data and data['plugins']:
            html += '<h3>Plugins</h3><table class="plugin-table"><thead><tr><th>Plugin</th><th>Version</th><th>Status</th><th>Vulnerabilities</th></tr></thead><tbody>'
            
            for slug, plugin_data in data['plugins'].items():
                version_data = plugin_data.get('version')
                if version_data and isinstance(version_data, dict):
                    version = version_data.get('number', 'Unknown')
                    version_detected = True
                else:
                    version = 'Not Detected'
                    version_detected = False
                
                vulns = plugin_data.get('vulnerabilities', [])
                vuln_count = len(vulns)
                
                if vuln_count > 0:
                    if version_detected and version != 'Unknown':
                        status = '<span class="badge badge-danger">Vulnerable</span>'
                        vuln_text = f'{vuln_count} confirmed'
                    else:
                        status = '<span class="badge badge-warning">Unknown</span>'
                        vuln_text = f'{vuln_count} possible'
                else:
                    status = '<span class="badge badge-success">Safe</span>'
                    vuln_text = 'None'
                
                html += f'<tr><td><strong>{slug}</strong></td><td>{version}</td><td>{status}</td><td>{vuln_text}</td></tr>'
                
                # Vulnerability details
                if vuln_count > 0:
                    html += f'<tr><td colspan="4">'
                    if not version_detected:
                        html += '<div class="warning-box"><strong>⚠️ Version Not Detected:</strong> Cannot confirm if vulnerable. Check WordPress admin for actual version.</div>'
                    for vuln in vulns:
                        vuln_title = vuln.get("title", "Unknown Vulnerability")
                        severity_class, severity_text = get_severity(vuln_title)
                        html += f'<div class="vuln-details {severity_class}">'
                        html += f'<div class="vuln-title">{vuln_title}<span class="severity-badge severity-{severity_class}">{severity_text}</span></div>'
                        html += '<div class="vuln-meta">'
                        if vuln.get('fixed_in'):
                            html += f'<strong>Fixed in:</strong> v{vuln["fixed_in"]} | '
                        if vuln.get('references', {}).get('cve'):
                            cves = ', '.join(vuln['references']['cve'][:3])
                            html += f'<strong>CVE:</strong> {cves}'
                        html += '</div></div>'
                    html += '</td></tr>'
            
            html += '</tbody></table>'
        
        html += '</div>'
    
    html += '</div></body></html>'
    return html


def print_summary(results: List[Dict[str, Any]]):
    """Print summary of all scans"""
    print(f"\n{'='*100}")
    print(f"📊 OVERALL SUMMARY")
    print(f"{'='*100}\n")
    
    total = len(results)
    successful = sum(1 for r in results if r['status'] == 'success')
    errors = total - successful
    
    total_plugins = 0
    vulnerable_plugins = 0
    total_vulns = 0
    
    for result in results:
        if result['status'] == 'success':
            data = result['data']
            
            # Count plugins
            if 'plugins' in data:
                site_plugins = data['plugins']
                total_plugins += len(site_plugins)
                
                for plugin_data in site_plugins.values():
                    vulns = plugin_data.get('vulnerabilities', [])
                    if vulns:
                        vulnerable_plugins += 1
                        total_vulns += len(vulns)
            
            # Count theme vulnerabilities
            if 'main_theme' in data:
                total_vulns += len(data['main_theme'].get('vulnerabilities', []))
            
            # Count WordPress core vulnerabilities
            if 'version' in data:
                total_vulns += len(data['version'].get('vulnerabilities', []))
    
    print(f"Sites scanned: {total}")
    print(f"Successful scans: {successful}")
    print(f"Failed scans: {errors}")
    print(f"\nPlugins found: {total_plugins}")
    print(f"Vulnerable plugins: {vulnerable_plugins}")
    print(f"Safe plugins: {total_plugins - vulnerable_plugins}")
    print(f"\nTotal vulnerabilities: {total_vulns}")
    
    if total_vulns == 0 and successful > 0:
        print(f"\n✅ All sites are secure - no vulnerabilities detected!")
    elif total_vulns > 0:
        print(f"\n⚠️  Action required: {total_vulns} vulnerabilities need attention")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='WPScan CLI Wrapper - Plugin Security Report',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --token YOUR_TOKEN --url example.com
  %(prog)s --token YOUR_TOKEN --urls site1.com site2.com site3.com
  %(prog)s --token YOUR_TOKEN --url-file urls.txt
  %(prog)s --token YOUR_TOKEN --url example.com --aggressive
        """
    )
    
    parser.add_argument(
        '--token',
        default=os.environ.get('WPSCAN_API_TOKEN'),
        help='Your WPScan API token (or set WPSCAN_API_TOKEN env variable)'
    )
    
    parser.add_argument(
        '--url',
        help='Single WordPress site URL to scan'
    )
    
    parser.add_argument(
        '--urls',
        nargs='+',
        help='Multiple WordPress site URLs (space-separated)'
    )
    
    parser.add_argument(
        '--url-file',
        help='File containing URLs (one per line)'
    )
    
    parser.add_argument(
        '--enumerate',
        default='vp',
        help='Enumeration options: vp (vulnerable plugins), ap (all plugins), vt (vulnerable themes), etc. (default: vp)'
    )
    
    parser.add_argument(
        '--plugins-detection',
        choices=['passive', 'aggressive', 'mixed'],
        default='passive',
        help='Plugin detection mode (default: passive)'
    )
    
    parser.add_argument(
        '--aggressive',
        action='store_true',
        help='Use aggressive scanning (detects all plugins, not just vulnerable ones)'
    )
    
    parser.add_argument(
        '--disable-tls-checks',
        action='store_true',
        help='Disable SSL/TLS certificate verification'
    )
    
    parser.add_argument(
        '--max-workers',
        type=int,
        default=3,
        help='Maximum concurrent scans (default: 3)'
    )
    
    parser.add_argument(
        '--output',
        help='Save results to JSON file'
    )
    
    parser.add_argument(
        '--html-report',
        nargs='?',
        const='wpscan_report_{}.html'.format(datetime.now().strftime('%Y%m%d_%H%M%S')),
        default='wpscan_report_{}.html'.format(datetime.now().strftime('%Y%m%d_%H%M%S')),
        help='Save results as HTML report (default: auto-generated filename)'
    )
    
    parser.add_argument(
        '--no-html',
        action='store_true',
        help='Disable automatic HTML report generation'
    )
    
    args = parser.parse_args()
    
    # Check for API token
    if not args.token:
        print("❌ Error: API token required!")
        print("\nProvide token via:")
        print("  --token YOUR_TOKEN")
        print("  or set WPSCAN_API_TOKEN environment variable")
        sys.exit(1)
    
    # Collect URLs
    urls = []
    if args.url:
        urls.append(args.url)
    if args.urls:
        urls.extend(args.urls)
    if args.url_file:
        try:
            with open(args.url_file, 'r') as f:
                file_urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                urls.extend(file_urls)
        except FileNotFoundError:
            print(f"❌ File not found: {args.url_file}")
            sys.exit(1)
    
    if not urls:
        parser.print_help()
        print("\n❌ Error: Please specify at least one URL to scan")
        sys.exit(1)
    
    # Prepare scan options
    options = {
        'enumerate': 'ap,at,cb,dbe' if args.aggressive else args.enumerate,
        'plugins_detection': 'aggressive' if args.aggressive else args.plugins_detection,
        'detection_mode': 'aggressive' if args.aggressive else 'passive',
        'disable_tls_checks': args.disable_tls_checks
    }
    
    # Initialize scanner
    scanner = WPScanCLI(args.token)
    
    print(f"\n🚀 Starting WPScan Plugin Security Report")
    print(f"⏰ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"📋 Scanning {len(urls)} site(s)")
    print(f"⚙️  Mode: {'Aggressive (All Plugins)' if args.aggressive else 'Standard (Vulnerable Only)'}\n")
    
    # Scan sites
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.max_workers) as executor:
        future_to_url = {executor.submit(scanner.scan_site, url, options): url for url in urls}
        
        for future in concurrent.futures.as_completed(future_to_url):
            result = future.result()
            results.append(result)
            print_plugin_report(result)
    
    # Print summary
    print_summary(results)
    
    # Save to file if requested
    if args.output:
        try:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\n💾 Results saved to: {args.output}")
        except Exception as e:
            print(f"\n❌ Failed to save results: {e}")
    
    # Generate HTML report (automatic unless disabled)
    if not args.no_html and args.html_report:
        try:
            html_content = generate_html_report(results)
            with open(args.html_report, 'w', encoding='utf-8') as f:
                f.write(html_content)
            print(f"\n📄 HTML report saved to: {args.html_report}")
        except Exception as e:
            print(f"\n❌ Failed to save HTML report: {e}")
    
    print(f"\n✅ Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")


if __name__ == '__main__':
    main()
