LIGHT_CSS = """
* {
    box-sizing: border-box;
}

body {
    font-family: Verdana, sans-serif;
    font-size: 11pt;
    line-height: 1.6;
    color: #1a1a1a;
    background: #ffffff;
    margin: 0;
    padding: 0;
}

h1, h2, h3, h4, h5, h6 {
    font-weight: 600;
    margin-top: 1.4em;
    margin-bottom: 0.4em;
    line-height: 1.3;
}

h1 { font-size: 1.8em; border-bottom: 2px solid #d0d0d0; padding-bottom: 0.2em; }
h2 { font-size: 1.4em; border-bottom: 1px solid #e0e0e0; padding-bottom: 0.15em; }
h3 { font-size: 1.15em; }

p { margin: 0.6em 0; }

a { color: #0969da; }

code {
    font-family: ui-monospace, "Cascadia Code", "Fira Mono", monospace;
    font-size: 0.88em;
    background: #f0f0f0;
    border: 1px solid #ddd;
    border-radius: 3px;
    padding: 0.1em 0.35em;
}

pre.highlight {
    background: #f6f8fa;
    border: 1px solid #d0d7de;
    border-radius: 5px;
    padding: 0.8em 1em;
    margin: 0.8em 0;
    overflow-wrap: break-word;
    white-space: pre-wrap;
}

pre.highlight code {
    font-family: ui-monospace, "Cascadia Code", "Fira Mono", monospace;
    font-size: 0.85em;
    background: transparent;
    border: none;
    padding: 0;
    border-radius: 0;
    overflow-wrap: break-word;
    white-space: pre-wrap;
}

table {
    border-collapse: collapse;
    width: 100%;
    margin: 1em 0;
    font-size: 0.95em;
}

th, td {
    border: 1px solid #c0c0c0;
    padding: 0.45em 0.8em;
    text-align: left;
    vertical-align: top;
}

th {
    background: #c8e6c9;
    font-weight: 600;
    color: #1a1a1a;
}

tr:nth-child(even) td {
    background: #f0f7f0;
}

blockquote {
    border-left: 4px solid #c0c0c0;
    margin: 0.8em 0;
    padding: 0.4em 1em;
    color: #555;
    background: #f9f9f9;
}

hr {
    border: none;
    border-top: 1px solid #d0d0d0;
    margin: 1.5em 0;
}

ul, ol {
    margin: 0.5em 0;
    padding-left: 1.8em;
}

li { margin: 0.2em 0; }

@page {
    margin: 2cm;
}
"""

DARK_CSS = """
* {
    box-sizing: border-box;
}

body {
    font-family: Verdana, sans-serif;
    font-size: 11pt;
    line-height: 1.6;
    color: #e0e0e0;
    background: #1e1e1e;
    margin: 0;
    padding: 0;
}

h1, h2, h3, h4, h5, h6 {
    font-weight: 600;
    margin-top: 1.4em;
    margin-bottom: 0.4em;
    line-height: 1.3;
    color: #f0f0f0;
}

h1 { font-size: 1.8em; border-bottom: 2px solid #444; padding-bottom: 0.2em; }
h2 { font-size: 1.4em; border-bottom: 1px solid #383838; padding-bottom: 0.15em; }
h3 { font-size: 1.15em; }

p { margin: 0.6em 0; }

a { color: #58a6ff; }

code {
    font-family: ui-monospace, "Cascadia Code", "Fira Mono", monospace;
    font-size: 0.88em;
    background: #2d2d2d;
    border: 1px solid #444;
    border-radius: 3px;
    padding: 0.1em 0.35em;
    color: #e0e0e0;
}

pre.highlight {
    background: #252525;
    border: 1px solid #3a3a3a;
    border-radius: 5px;
    padding: 0.8em 1em;
    margin: 0.8em 0;
    overflow-wrap: break-word;
    white-space: pre-wrap;
}

pre.highlight code {
    font-family: ui-monospace, "Cascadia Code", "Fira Mono", monospace;
    font-size: 0.85em;
    background: transparent;
    border: none;
    padding: 0;
    border-radius: 0;
    color: #e0e0e0;
    overflow-wrap: break-word;
    white-space: pre-wrap;
}

table {
    border-collapse: collapse;
    width: 100%;
    margin: 1em 0;
    font-size: 0.95em;
}

th, td {
    border: 1px solid #4a4a4a;
    padding: 0.45em 0.8em;
    text-align: left;
    vertical-align: top;
}

th {
    background: #1e3d2a;
    font-weight: 600;
    color: #f0f0f0;
}

tr:nth-child(even) td {
    background: #242e24;
}

blockquote {
    border-left: 4px solid #555;
    margin: 0.8em 0;
    padding: 0.4em 1em;
    color: #aaa;
    background: #272727;
}

hr {
    border: none;
    border-top: 1px solid #444;
    margin: 1.5em 0;
}

ul, ol {
    margin: 0.5em 0;
    padding-left: 1.8em;
}

li { margin: 0.2em 0; }

@page {
    margin: 2cm;
}
"""
