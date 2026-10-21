"""Verify flags work with runtime-selected panel/subscription base paths."""
import base64
from pathlib import Path
import re

root = Path(__file__).resolve().parents[1]
dist = root / 'internal/web/dist'
for entry in ('index.html', 'login.html', 'subpage.html'):
    html = (dist / entry).read_text(encoding='utf-8')
    styles = re.findall(r'href="(/assets/[^\"]+\.css)"', html)
    css = '\n'.join((dist / style.lstrip('/')).read_text(encoding='utf-8') for style in styles)
    assert 'Country Flags' in css, f'{entry}: missing country font'
    rule = re.search(r'@font-face\{[^}]*font-family:(?:\"|\')?Country Flags[^}]*\}', css)
    assert rule, f'{entry}: missing font face'
    url = re.search(r'url\(([^)]+)\)', rule[0])[1].strip('\"\'')
    assert url.startswith('data:font/woff2;base64,'), f'{entry}: font depends on absolute /assets/ path'
    font = base64.b64decode(url.split(',', 1)[1])
    assert font == (root / 'frontend/src/assets/fonts/TwemojiCountryFlags.woff2').read_bytes()
    print(f'PASS {entry}: inline country flags independent of panel or subscription path')
