from flask import Flask, request, render_template, jsonify, send_file
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import joblib, sqlite3, json, requests, base64
from datetime import datetime
from feature_extractor import extract_features
from fpdf import FPDF
import io

app = Flask(__name__)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per hour"]
)

model = joblib.load('model/phishing_model.pkl')

# ── PASTE YOUR VIRUSTOTAL API KEY HERE ──────────────────────
VT_API_KEY = '60ff2d36ec967b463f852cfae9697f6c90e01a30985678800905fb99560559ab'
# ────────────────────────────────────────────────────────────

FEATURE_NAMES = [
    'IP Address in URL', 'URL Length', 'URL Shortener', 'At Symbol',
    'Double Slash Redirect', 'Prefix/Suffix Dash', 'Subdomain Depth', 'SSL State',
    'Domain Reg. Length', 'Favicon Source', 'Non-Standard Port', 'HTTPS in Token',
    'Request URL Ratio', 'Anchor URL Ratio', 'Tag Link Ratio', 'Form Handler',
    'Email Submission', 'Abnormal URL', 'Redirect Count', 'Mouse Over Action',
    'Right Click Disabled', 'Popup Window', 'Iframe Usage', 'Domain Age',
    'DNS Record', 'Web Traffic', 'Page Rank', 'Google Index',
    'Inbound Links', 'Statistical Report'
]

DB_PATH = 'scans.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT,
        result TEXT,
        confidence REAL,
        risk_count INTEGER,
        safe_count INTEGER,
        neutral_count INTEGER,
        features TEXT,
        timestamp TEXT
    )''')
    conn.commit()
    conn.close()

init_db()

def save_scan(url, result, confidence, risk_count, safe_count, neutral_count, features):
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''INSERT INTO scans
        (url, result, confidence, risk_count, safe_count, neutral_count, features, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
        (url, result, confidence, risk_count, safe_count, neutral_count,
         json.dumps(features), datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    conn.commit()
    conn.close()

def get_history():
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute('SELECT * FROM scans ORDER BY id DESC LIMIT 20').fetchall()
    conn.close()
    return rows

def get_stats():
    conn = sqlite3.connect(DB_PATH)
    total = conn.execute('SELECT COUNT(*) FROM scans').fetchone()[0]
    phishing = conn.execute("SELECT COUNT(*) FROM scans WHERE result='Phishing'").fetchone()[0]
    legit = conn.execute("SELECT COUNT(*) FROM scans WHERE result='Legitimate'").fetchone()[0]
    conn.close()
    return {'total': total, 'phishing': phishing, 'legitimate': legit}

def check_virustotal(url):
    try:
        headers = {'x-apikey': VT_API_KEY}
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
        r = requests.get(
            f'https://www.virustotal.com/api/v3/urls/{url_id}',
            headers=headers,
            timeout=10
        )
        if r.status_code == 200:
            data = r.json()
            stats = data['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total = sum(stats.values())
            if malicious >= 2:
                verdict = 'phishing'
            elif suspicious >= 2:
                verdict = 'suspicious'
            else:
                verdict = 'clean'
            return {
                'found': True,
                'malicious': malicious,
                'suspicious': suspicious,
                'total': total,
                'verdict': verdict
            }
        elif r.status_code == 404:
            # URL not in VT yet — submit it for future scans
            requests.post(
                'https://www.virustotal.com/api/v3/urls',
                headers=headers,
                data={'url': url},
                timeout=10
            )
            return {'found': False, 'verdict': 'unknown'}
        else:
            return {'found': False, 'verdict': 'unknown'}
    except Exception:
        return {'found': False, 'verdict': 'unknown'}

def analyze_url(url):
    features = extract_features(url)
    prediction = model.predict([features])[0]
    proba = model.predict_proba([features])[0]
    is_phishing = prediction == -1
    confidence = round(proba[0] * 100 if is_phishing else proba[1] * 100, 1)

    feature_details = []
    safe_count = neutral_count = risk_count = 0
    for name, val in zip(FEATURE_NAMES, features):
        if val == 1:
            status = 'safe'; safe_count += 1
        elif val == 0:
            status = 'neutral'; neutral_count += 1
        else:
            status = 'risk'; risk_count += 1
        feature_details.append({'name': name, 'value': val, 'status': status})

    # ── VirusTotal check ────────────────────────────────────────
    full_url = url if url.startswith('http') else 'https://' + url
    vt_result = check_virustotal(full_url)
    vt_label = None
    vt_verdict = vt_result['verdict']

    if vt_verdict == 'phishing':
        is_phishing = True
        confidence = max(confidence, 92.0)
        vt_label = f"VirusTotal: {vt_result['malicious']} out of {vt_result['total']} engines flagged as malicious"
    elif vt_verdict == 'suspicious':
        is_phishing = True
        confidence = max(confidence, 72.0)
        vt_label = f"VirusTotal: {vt_result['suspicious']} out of {vt_result['total']} engines flagged as suspicious"
    elif vt_verdict == 'clean':
        if not is_phishing:
            confidence = max(confidence, 85.0)
        vt_label = f"VirusTotal: Clean — scanned by {vt_result['total']} engines, no threats found"
    else:
        vt_label = "VirusTotal: URL not in database yet — ML model used for prediction"
    # ────────────────────────────────────────────────────────────

    # ── ML Override logic ───────────────────────────────────────
    FREE_HOST_KEYWORDS = ['blogspot', 'weebly', 'wixsite', 'netlify',
                          '000webhostapp', 'freehostia', 'byethost']
    url_lower = url.lower()

    if not is_phishing and any(h in url_lower for h in FREE_HOST_KEYWORDS):
        is_phishing = True
        confidence = max(confidence, 75.0)
    elif not is_phishing and risk_count >= 10:
        is_phishing = True
        confidence = min(round(50 + (risk_count * 2.5), 1), 95.0)
    elif not is_phishing and confidence < 55:
        is_phishing = True
        confidence = round(100 - confidence, 1)
    elif not is_phishing and risk_count > (safe_count * 2) and risk_count >= 8:
        is_phishing = True
        confidence = round(55 + (risk_count - safe_count) * 1.5, 1)

    result_label = 'Phishing' if is_phishing else 'Legitimate'
    # ────────────────────────────────────────────────────────────

    return {
        'url': url,
        'result': result_label,
        'is_phishing': is_phishing,
        'confidence': confidence,
        'feature_details': feature_details,
        'safe_count': safe_count,
        'neutral_count': neutral_count,
        'risk_count': risk_count,
        'features': features,
        'vt_label': vt_label,
        'vt_verdict': vt_verdict
    }

@app.route('/')
def home():
    stats = get_stats()
    return render_template('index.html', stats=stats)

@app.route('/predict', methods=['POST'])
@limiter.limit("20 per minute")
def predict():
    url = request.form.get('url', '').strip()
    if not url:
        return render_template('index.html', error='Please enter a URL.', stats=get_stats())
    try:
        data = analyze_url(url)
        save_scan(data['url'], data['result'], data['confidence'],
                  data['risk_count'], data['safe_count'], data['neutral_count'],
                  data['features'])
        return render_template('result.html', **data,
                               timestamp=datetime.now().strftime('%d %b %Y, %H:%M'))
    except Exception as e:
        return render_template('index.html', error=f'Error: {str(e)}', stats=get_stats())

@app.route('/api/scan', methods=['POST'])
@limiter.limit("10 per minute")
def api_scan():
    data = request.get_json()
    url = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'URL required'}), 400
    try:
        result = analyze_url(url)
        save_scan(result['url'], result['result'], result['confidence'],
                  result['risk_count'], result['safe_count'], result['neutral_count'],
                  result['features'])
        return jsonify({
            'url': result['url'],
            'result': result['result'],
            'confidence': result['confidence'],
            'risk_flags': result['risk_count'],
            'safe_features': result['safe_count'],
            'virustotal': result['vt_label']
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/history')
def history():
    rows = get_history()
    scans = []
    for r in rows:
        scans.append({
            'id': r[0], 'url': r[1], 'result': r[2],
            'confidence': r[3], 'risk_count': r[4],
            'safe_count': r[5], 'timestamp': r[8]
        })
    stats = get_stats()
    return render_template('history.html', scans=scans, stats=stats)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/export/<int:scan_id>')
def export_pdf(scan_id):
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute('SELECT * FROM scans WHERE id=?', (scan_id,)).fetchone()
    conn.close()
    if not row:
        return 'Scan not found', 404

    features = json.loads(row[7])
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font('Helvetica', 'B', 20)
    pdf.cell(0, 12, 'PhishGuard - Scan Report', ln=True)
    pdf.set_font('Helvetica', '', 11)
    pdf.cell(0, 8, f'URL: {row[1]}', ln=True)
    pdf.cell(0, 8, f'Result: {row[2]}', ln=True)
    pdf.cell(0, 8, f'Confidence: {row[3]}%', ln=True)
    pdf.cell(0, 8, f'Timestamp: {row[8]}', ln=True)
    pdf.cell(0, 8, f'Risk Flags: {row[4]}  |  Safe: {row[5]}  |  Neutral: {row[6]}', ln=True)
    pdf.ln(6)
    pdf.set_font('Helvetica', 'B', 13)
    pdf.cell(0, 8, 'Feature Analysis:', ln=True)
    pdf.set_font('Helvetica', '', 10)
    for name, val in zip(FEATURE_NAMES, features):
        status = 'SAFE' if val == 1 else ('NEUTRAL' if val == 0 else 'RISK')
        pdf.cell(0, 6, f'  {name}: {status} ({val})', ln=True)

    buf = io.BytesIO()
    pdf.output(buf)
    buf.seek(0)
    return send_file(buf, as_attachment=True,
                     download_name=f'phishguard_report_{scan_id}.pdf',
                     mimetype='application/pdf')

@app.route('/bulk')
def bulk():
    return render_template('bulk.html')

@app.route('/bulk/scan', methods=['POST'])
@limiter.limit("5 per minute")
def bulk_scan():
    raw = request.form.get('urls', '')
    urls = [u.strip() for u in raw.strip().splitlines() if u.strip()]
    urls = urls[:20]
    results = []
    for url in urls:
        try:
            data = analyze_url(url)
            save_scan(data['url'], data['result'], data['confidence'],
                      data['risk_count'], data['safe_count'], data['neutral_count'],
                      data['features'])
            results.append({
                'url': url,
                'result': data['result'],
                'confidence': data['confidence'],
                'risk_count': data['risk_count'],
                'safe_count': data['safe_count'],
                'is_phishing': data['is_phishing']
            })
        except Exception as e:
            results.append({
                'url': url,
                'result': 'Error',
                'confidence': 0,
                'risk_count': 0,
                'safe_count': 0,
                'is_phishing': False,
                'error': str(e)
            })
    total = len(results)
    phishing_count = sum(1 for r in results if r['result'] == 'Phishing')
    return render_template('bulk_result.html',
        results=results, total=total, phishing_count=phishing_count,
        legit_count=total - phishing_count)

@app.route('/threats')
def threats():
    return render_template('threats.html')

@app.route('/api/threats')
def api_threats():
    try:
        import urllib.request
        req = urllib.request.Request(
            'https://openphish.com/feed.txt',
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            content = resp.read().decode('utf-8')
        urls = [u.strip() for u in content.strip().splitlines() if u.strip()][:50]
        feed = [{'url': u, 'source': 'OpenPhish', 'type': 'Phishing',
                 'timestamp': datetime.now().strftime('%Y-%m-%d')} for u in urls]
        return jsonify({'status': 'ok', 'count': len(feed), 'feed': feed})
    except Exception as e:
        sample = [
            {'url': 'http://paypal-security-login.com/verify', 'source': 'OpenPhish', 'type': 'Phishing', 'timestamp': datetime.now().strftime('%Y-%m-%d')},
            {'url': 'http://192.168.1.1/bank/login.php', 'source': 'OpenPhish', 'type': 'Phishing', 'timestamp': datetime.now().strftime('%Y-%m-%d')},
            {'url': 'http://amazon-account-suspended.tk/login', 'source': 'OpenPhish', 'type': 'Phishing', 'timestamp': datetime.now().strftime('%Y-%m-%d')},
            {'url': 'http://secure-netbank-verify.xyz/auth', 'source': 'OpenPhish', 'type': 'Phishing', 'timestamp': datetime.now().strftime('%Y-%m-%d')},
            {'url': 'http://microsoft-account-alert.ml/signin', 'source': 'OpenPhish', 'type': 'Phishing', 'timestamp': datetime.now().strftime('%Y-%m-%d')},
        ]
        return jsonify({'status': 'fallback', 'count': len(sample), 'feed': sample})

@app.route('/extension')
def extension():
    return render_template('extension.html')

@app.route('/delete/<int:scan_id>', methods=['POST'])
def delete_scan(scan_id):
    conn = sqlite3.connect(DB_PATH)
    conn.execute('DELETE FROM scans WHERE id=?', (scan_id,))
    conn.commit()
    conn.close()
    return jsonify({'status': 'deleted'})

if __name__ == '__main__':
    app.run(debug=True)