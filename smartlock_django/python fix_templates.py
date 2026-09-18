"""Chạy từ thư mục chứa manage.py:  python fix_templates.py
- Đưa {% extends %} lên dòng đầu tiên của mọi template.
- Đổi {{ x or "abc" }} -> {{ x|default:"abc" }} (Django không hỗ trợ `or` trong biến).
Bản gốc được copy sang templates_backup/ trước khi sửa.
"""
import re
import shutil
from pathlib import Path

ROOT = Path('templates')
BACKUP = Path('templates_backup')

EXTENDS = re.compile(r'^[ \t]*\{%\s*extends\s+[^%]+%\}[ \t]*\r?\n?', re.M)
OR_EXPR = re.compile(r'\{\{\s*([\w.]+)\s+or\s+("[^"]*"|\'[^\']*\')\s*\}\}')

if not ROOT.is_dir():
    raise SystemExit('Không thấy thư mục templates/ - chạy script ở thư mục chứa manage.py')
if not BACKUP.exists():
    shutil.copytree(ROOT, BACKUP)

for f in sorted(ROOT.rglob('*.html')):
    text = f.read_text(encoding='utf-8')
    new = text
    m = EXTENDS.search(new)
    if m and new[:m.start()].strip():
        line = m.group(0).strip()
        new = new[:m.start()] + new[m.end():]
        new = line + '\n' + new.lstrip('\r\n')
    new = OR_EXPR.sub(lambda mo: '{{ %s|default:%s }}' % (mo.group(1), mo.group(2)), new)
    if new != text:
        f.write_text(new, encoding='utf-8', newline='')
        print('đã sửa:', f)
print('xong.')