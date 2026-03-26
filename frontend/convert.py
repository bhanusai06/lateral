import re

with open("lateralshield-landing.html", "r", encoding="utf-8") as f:
    text = f.read()

style_match = re.search(r"<style>(.*?)</style>", text, re.DOTALL)
css = style_match.group(1).strip() if style_match else ""

with open("LateralShieldLanding.css", "w", encoding="utf-8") as f:
    f.write(css)

body_match = re.search(r"<body>(.*?)<script>", text, re.DOTALL)
html = body_match.group(1).strip() if body_match else ""

script_match = re.search(r"<script>(.*?)</script>", text, re.DOTALL)
js = script_match.group(1).strip() if script_match else ""

# Replace single tags
html = html.replace("<br>", "<br />")

# class to className
html = html.replace('class="', 'className="')

# style string to object
def replace_style(m):
    s = m.group(1).strip()
    parts = s.split(';')
    obj = {}
    for p in parts:
        if not p.strip(): continue
        if ':' not in p: continue
        k, v = p.split(':', 1)
        k = k.strip()
        v = v.strip()
        # camelCase k
        k = re.sub(r'-([a-z])', lambda x: x.group(1).upper(), k)
        obj[k] = v
    
    # format dict as react style object
    items = []
    for k, v in obj.items():
        if v.isdigit():
            items.append(f"{k}: {v}")
        else:
            items.append(f"{k}: '{v}'")
    js_obj = ", ".join(items)
    return f"style={{{{ {js_obj} }}}}"

html = re.sub(r'style="([^"]+)"', replace_style, html)

# SVG props
html = html.replace("stroke-dasharray=", "strokeDasharray=")
html = html.replace("stroke-width=", "strokeWidth=")
html = html.replace("stroke-dashoffset=", "strokeDashoffset=")
html = html.replace("stroke-linecap=", "strokeLinecap=")

# JSX Comments
html = re.sub(r'<!--(.*?)-->', r'{/* \1 */}', html)

# onClick function args
html = re.sub(r'onclick="([^"]+)"', r'onClick={() => window.\1}', html)

js += '''
window.runSim = runSim;
window.clearTerm = clearTerm;
window.scrollToDashboard = scrollToDashboard;
window.showDashboardMsg = showDashboardMsg;
'''

react_component = f"""import React, {{ useEffect }} from 'react';
import './LateralShieldLanding.css';

export default function LateralShieldLanding() {{
  useEffect(() => {{
    {js}
  }}, []);

  return (
    <>
      {html}
    </>
  );
}}
"""

with open("LateralShieldLanding.jsx", "w", encoding="utf-8") as f:
    f.write(react_component)

print("Conversion complete.")
