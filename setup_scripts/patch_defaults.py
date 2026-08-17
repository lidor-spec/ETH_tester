import io, sys
p = r'C:\Users\lidor\ETH-Switch-Tester\eth_switch_tester.py'
s = io.open(p, encoding='utf-8').read()
subs = [
    ('self.v_link = tk.StringVar(value="1000")',
     'self.v_link = tk.StringVar(value="100")'),
    ('    link_mbps: int = 1000',
     '    link_mbps: int = 100'),
    ('values=["10", "100", "1000", "2500"]',
     'values=["10", "100", "1000"]'),
]
n = 0
for a, b in subs:
    if a in s:
        s = s.replace(a, b, 1)
        n += 1
        print('patched:', a.strip()[:60])
    else:
        print('NOT FOUND:', a.strip()[:60])
io.open(p, 'w', encoding='utf-8').write(s)
print('%d/%d substitutions applied' % (n, len(subs)))
