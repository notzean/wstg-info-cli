import datetime
import json

def generate_html(results, target_url, output_file):
    date_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WSTG-INFO Report - {target_url}</title>
    <style>
        :root {{
            --bg-color: #f4f7f6;
            --text-color: #333;
            --card-bg: #fff;
            --primary: #2c3e50;
            --success: #27ae60;
            --warning: #f39c12;
            --danger: #e74c3c;
            --border: #ddd;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            line-height: 1.6;
            margin: 0;
            padding: 20px;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
        }}
        header {{
            background: var(--primary);
            color: #fff;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            text-align: center;
        }}
        .card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
        }}
        .card-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 10px;
            margin-bottom: 15px;
        }}
        .card-title {{
            margin: 0;
            font-size: 1.2em;
            color: var(--primary);
        }}
        .status {{
            padding: 5px 10px;
            border-radius: 4px;
            font-size: 0.9em;
            font-weight: bold;
            color: #fff;
            text-transform: uppercase;
        }}
        .status.completed {{ background-color: var(--success); }}
        .status.partial {{ background-color: var(--warning); }}
        .status.error {{ background-color: var(--danger); }}
        
        details {{
            margin-bottom: 10px;
            border: 1px solid var(--border);
            border-radius: 4px;
        }}
        summary {{
            padding: 10px;
            background-color: #f9f9f9;
            cursor: pointer;
            font-weight: bold;
        }}
        .details-content {{
            padding: 15px;
            border-top: 1px solid var(--border);
            background-color: #fff;
            overflow-x: auto;
        }}
        pre {{
            background: #2b2b2b;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 4px;
            white-space: pre-wrap;
            word-wrap: break-word;
            font-family: 'Courier New', Courier, monospace;
            font-size: 0.9em;
        }}
        @media print {{
            .no-print {{ display: none !important; }}
            body {{ background: #fff; color: #000; padding: 0; }}
            .container {{ max-width: 100% !important; margin: 0; padding: 0; }}
            .card {{ box-shadow: none; border: 1px solid #ccc; page-break-inside: avoid; margin-bottom: 20px; }}
            pre {{ background: #f4f4f4; color: #000; border: 1px solid #ddd; white-space: pre-wrap; word-break: break-all; }}
            header {{ background: #fff; color: #000; border: 1px solid #ccc; }}
            .status.completed {{ color: #000; border: 1px solid var(--success); background: transparent; }}
            .status.error {{ color: #000; border: 1px solid var(--danger); background: transparent; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>WSTG-INFO Security Report</h1>
            <p>Target: <strong>{target_url}</strong></p>
            <p>Generated: {date_str}</p>
            <button class="no-print" onclick="exportPDF()" style="margin-top: 15px; padding: 10px 20px; background-color: var(--success); color: white; border: none; border-radius: 5px; font-size: 1em; cursor: pointer; font-weight: bold; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">📄 Export as PDF</button>
        </header>
"""

    for res in results:
        status_class = res.get('status', 'error')
        wstg_id = res.get('wstg_id', 'UNKNOWN')
        title = res.get('title', 'Unknown Module')
        findings = res.get('findings', [])
        error = res.get('error')
        
        html_content += f"""
        <div class="card">
            <div class="card-header">
                <h2 class="card-title">{wstg_id}: {title}</h2>
                <span class="status {status_class}">{status_class}</span>
            </div>
            <div class="card-body">
"""
        
        if error:
            html_content += f'<div style="color: var(--danger); font-weight: bold; margin-bottom: 10px;">Error: {error}</div>\n'
            
        if not findings and not error:
            html_content += '<p>Tidak ada temuan.</p>\n'
            
        for finding in findings:
            category = finding.get('category', 'Finding')
            data = finding.get('data', '')
            
            if "Mermaid" in category:
                data_formatted = f"<div class='mermaid'>\n{data}\n</div>"
            elif isinstance(data, (dict, list)):
                data_formatted = f"<pre>{json.dumps(data, indent=2)}</pre>"
            else:
                data_formatted = f"<pre>{data}</pre>"
                
            html_content += f"""
                <details>
                    <summary>{category}</summary>
                    <div class="details-content">
                        {data_formatted}
                    </div>
                </details>
"""
        
        html_content += """
            </div>
        </div>
"""

    html_content += """
    </div>
    <script type="module">
        import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
        mermaid.initialize({ startOnLoad: true });
    </script>
    <script>
        function exportPDF() {
            document.querySelectorAll('details').forEach(detail => {
                detail.open = true;
            });
            setTimeout(() => {
                window.print();
            }, 100);
        }
    </script>
</body>
</html>
"""

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
