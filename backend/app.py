from flask import Flask, request, jsonify
from flask_cors import CORS
import subprocess
import os

app = Flask(__name__)
CORS(app)

PORTSCAN_SCRIPT = os.path.join('scans', 'portscan.py')  # portscan.py'nin yolu

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    target = data.get('target')
    port_start = data.get('port_start')
    port_end = data.get('port_end')

    if not target or not port_start or not port_end:
        return jsonify({'error': 'IP, port başlangıç ve bitiş değerleri gerekli'}), 400

    ips_file = os.path.join(os.path.dirname(PORTSCAN_SCRIPT), 'ips.txt')

    try:
        with open(ips_file, 'w', encoding='utf-8') as f:
            f.write(f"{target},{port_start},{port_end}\n")
    except Exception as e:
        return jsonify({'error': f'ips.txt yazılamadı: {str(e)}'}), 500

    try:
        result = subprocess.run(
            ['python', '-u', 'portscan.py'],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(PORTSCAN_SCRIPT),
            shell=False 
        )

        print("STDOUT:", result.stdout)
        print("STDERR:", result.stderr)
        print("RETURNCODE:", result.returncode)

        return jsonify({
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
