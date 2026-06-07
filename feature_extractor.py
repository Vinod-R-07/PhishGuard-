import re
import requests
import whois
import tldextract
from bs4 import BeautifulSoup
from datetime import datetime
from urllib.parse import urlparse

FREE_HOSTS = ['blogspot', 'weebly', 'wixsite', 'wordpress', 'netlify',
              'pages.dev', '000webhostapp', 'freehostia', 'byethost']

SHORTENERS = ['bit.ly', 'goo.gl', 'tinyurl', 'ow.ly', 't.co', 'is.gd',
              'buff.ly', 'adf.ly', 'short.link', 'cutt.ly']

def extract_features(url):
    features = []

    if not url.startswith('http'):
        full_url = 'https://' + url
    else:
        full_url = url

    try:
        response = requests.get(full_url, timeout=5, allow_redirects=True)
        soup = BeautifulSoup(response.text, 'html.parser')
        site_reachable = True
    except:
        soup = None
        response = None
        site_reachable = False

    if not site_reachable:
        return [-1] * 30

    parsed = urlparse(full_url)
    ext = tldextract.extract(full_url)
    domain = ext.domain + '.' + ext.suffix
    full_domain = parsed.netloc

    # 1. having_IP_Address
    features.append(-1 if re.match(r'\d+\.\d+\.\d+\.\d+', full_domain) else 1)

    # 2. URL_Length
    length = len(full_url)
    features.append(1 if length < 54 else (0 if length <= 75 else -1))

    # 3. Shortening_Service
    features.append(-1 if any(s in full_url for s in SHORTENERS) else 1)

    # 4. having_At_Symbol
    features.append(-1 if '@' in full_url else 1)

    # 5. double_slash_redirecting
    path = parsed.path
    features.append(-1 if '//' in path else 1)

    # 6. Prefix_Suffix
    features.append(-1 if '-' in full_domain else 1)

    # 7. having_Sub_Domain — free hosting treated as suspicious
    sub = ext.subdomain
    if any(h in domain for h in FREE_HOSTS):
        features.append(-1)
    else:
        dots = sub.count('.') if sub else 0
        features.append(1 if dots == 0 else (0 if dots == 1 else -1))

    # 8. SSLfinal_State
    features.append(1 if full_url.startswith('https') else -1)

    # 9. Domain_registeration_length
    try:
        w = whois.whois(domain)
        exp = w.expiration_date
        if isinstance(exp, list):
            exp = exp[0]
        if exp is None:
            features.append(-1)
        else:
            remaining = (exp - datetime.now()).days
            features.append(-1 if remaining < 365 else 1)
    except:
        features.append(-1)

    # 10. Favicon
    try:
        icons = soup.find_all('link', rel=lambda r: r and 'icon' in r)
        if not icons:
            features.append(0)
        else:
            external = any(domain not in (i.get('href', '')) for i in icons)
            features.append(-1 if external else 1)
    except:
        features.append(-1)

    # 11. port
    features.append(-1 if parsed.port else 1)

    # 12. HTTPS_token
    features.append(-1 if 'https' in ext.domain.lower() else 1)

    # 13. Request_URL
    try:
        imgs = soup.find_all('img')
        if not imgs:
            features.append(0)
        else:
            external = sum(1 for i in imgs if domain not in i.get('src', ''))
            ratio = external / len(imgs)
            features.append(1 if ratio < 0.22 else (0 if ratio < 0.61 else -1))
    except:
        features.append(-1)

    # 14. URL_of_Anchor
    try:
        anchors = soup.find_all('a')
        if not anchors:
            features.append(0)
        else:
            external = sum(1 for a in anchors if domain not in a.get('href', ''))
            ratio = external / len(anchors)
            features.append(1 if ratio < 0.31 else (0 if ratio < 0.67 else -1))
    except:
        features.append(-1)

    # 15. Links_in_tags
    try:
        links = soup.find_all(['link', 'script'])
        if not links:
            features.append(0)
        else:
            external = sum(1 for l in links if domain not in (l.get('href', '') or l.get('src', '')))
            ratio = external / len(links)
            features.append(1 if ratio < 0.17 else (0 if ratio < 0.81 else -1))
    except:
        features.append(-1)

    # 16. SFH
    try:
        forms = soup.find_all('form')
        if not forms:
            features.append(1)
        else:
            actions = [f.get('action', '') for f in forms]
            if any(a == '' or a == 'about:blank' for a in actions):
                features.append(-1)
            elif any(domain not in a for a in actions if a.startswith('http')):
                features.append(0)
            else:
                features.append(1)
    except:
        features.append(-1)

    # 17. Submitting_to_email
    try:
        features.append(-1 if 'mailto:' in str(soup) else 1)
    except:
        features.append(-1)

    # 18. Abnormal_URL
    try:
        w = whois.whois(domain)
        features.append(1 if domain in str(w) else -1)
    except:
        features.append(-1)

    # 19. Redirect
    try:
        redirects = len(response.history)
        features.append(1 if redirects == 0 else (0 if redirects == 1 else -1))
    except:
        features.append(-1)

    # 20. on_mouseover
    try:
        features.append(-1 if 'onmouseover' in str(soup).lower() else 1)
    except:
        features.append(-1)

    # 21. RightClick
    try:
        features.append(-1 if 'contextmenu' in str(soup).lower() else 1)
    except:
        features.append(-1)

    # 22. popUpWidnow
    try:
        features.append(-1 if 'window.open' in str(soup).lower() else 1)
    except:
        features.append(-1)

    # 23. Iframe
    try:
        features.append(-1 if soup.find_all('iframe') else 1)
    except:
        features.append(-1)

    # 24. age_of_domain
    try:
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created is None:
            features.append(-1)
        else:
            age = (datetime.now() - created).days
            features.append(1 if age >= 365 else (0 if age >= 180 else -1))
    except:
        features.append(-1)

    # 25. DNSRecord
    try:
        w = whois.whois(domain)
        features.append(-1 if not w or not w.domain_name else 1)
    except:
        features.append(-1)

    # 26. web_traffic — neutral, cannot determine without API
    features.append(0)

    # 27. Page_Rank — neutral, cannot determine without API
    features.append(0)

    # 28. Google_Index
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        r = requests.get(f'https://www.google.com/search?q=site:{domain}',
                         timeout=5, headers=headers)
        features.append(1 if domain in r.text else -1)
    except:
        features.append(-1)

    # 29. Links_pointing_to_page — neutral, cannot determine without API
    features.append(0)

    # 30. Statistical_report — neutral default
    features.append(0)

    return features