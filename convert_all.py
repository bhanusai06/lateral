import re, os

def convert_to_react(html_path, out_jsx, out_css, comp_name):
    with open(html_path, "r", encoding="utf-8") as f:
        text = f.read()

    style_match = re.search(r"<style>(.*?)</style>", text, re.DOTALL)
    css = style_match.group(1).strip() if style_match else ""

    with open(out_css, "w", encoding="utf-8") as f:
        f.write(css)

    body_match = re.search(r"<body>(.*?)<script>", text, re.DOTALL)
    html = body_match.group(1).strip() if body_match else ""
    if not html:
        body_match = re.search(r"<body>(.*?)</body>", text, re.DOTALL)
        if body_match:
            html = body_match.group(1).strip()
            html = re.sub(r"<script>(.*?)</script>", "", html, flags=re.DOTALL)

    script_match = re.search(r"<script>(.*?)</script>", text, re.DOTALL)
    js = script_match.group(1).strip() if script_match else ""

    # Replace specific file URLs to frontend routes
    html = html.replace("lateralshield-landing.html", "/")
    html = html.replace("lateralshield-login.html", "/login")
    html = html.replace("lateralshield-dashboard.html", "/dashboard")
    js = js.replace("lateralshield-landing.html", "/")
    js = js.replace("lateralshield-login.html", "/login")
    js = js.replace("lateralshield-dashboard.html", "/dashboard")

    # SVG issues with viewBox
    html = html.replace("viewbox=", "viewBox=")
    html = html.replace("xmlns:xlink", "xmlnsXlink")

    # self-closing html tags
    html = re.sub(r'<br\s*>', r'<br />', html)
    html = re.sub(r'<hr\s*>', r'<hr />', html)
    html = re.sub(r'<input([^>]*?[^/])>', r'<input\1 />', html)
    html = re.sub(r'<img([^>]*?[^/])>', r'<img\1 />', html)

    # Class and attributes
    html = html.replace('class="', 'className="')
    html = html.replace('for="', 'htmlFor="')

    def replace_style(m):
        s = m.group(1).strip()
        parts = s.split(';')
        obj = {}
        for p in parts:
            if not p.strip() or ':' not in p: continue
            k, v = p.split(':', 1)
            k, v = k.strip(), v.strip()
            k = re.sub(r'-([a-z])', lambda x: x.group(1).upper(), k)
            obj[k] = v
        items = [f"{k}: '{v}'" for k, v in obj.items()]
        return f"style={{{{ {', '.join(items)} }}}}"

    html = re.sub(r'style="([^"]+)"', replace_style, html)

    props = ['stroke-dasharray', 'stroke-width', 'stroke-dashoffset', 'stroke-linecap', 'fill-rule', 'clip-rule', 'stroke-linejoin', 'clip-path']
    for p in props:
        camel = "".join(word.capitalize() if i > 0 else word for i, word in enumerate(p.split('-')))
        html = html.replace(p + '=', camel + '=')

    html = re.sub(r'<!--(.*?)-->', r'{/* \1 */}', html)

    # Some scripts refer to window directly or just execute functions. We expose them if they are onclick.
    html = re.sub(r'onclick="([^"]+)"', r'onClick={() => { window.\1 }}', html)
    # Expose inner functions
    fun_matches = re.finditer(r'function\s+([a-zA-Z0-9_]+)\s*\(', js)
    for fm in fun_matches:
        js += f"\nwindow.{fm.group(1)} = {fm.group(1)};"

    react_component = f"""import React, {{ useEffect }} from 'react';
import './{os.path.basename(out_css)}';

export default function {comp_name}() {{
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
    with open(out_jsx, "w", encoding="utf-8") as f:
        f.write(react_component)

convert_to_react("frontend-old/lateralshield-login.html", "frontend/src/LateralShieldLogin.jsx", "frontend/src/LateralShieldLogin.css", "LateralShieldLogin")
convert_to_react("frontend-old/lateralshield-dashboard.html", "frontend/src/LateralShieldDashboard.jsx", "frontend/src/LateralShieldDashboard.css", "LateralShieldDashboard")
print("Conversion completed successfully.")
