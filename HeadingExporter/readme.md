**HeadingExporter** is designed to quickly export all headings and subheadings from a `.docx` file. Such as for the usecase if you are presenting a `.docx` file and want to make notes from what has been said on each heading.

## Required Python packages
- `python-docx`: `python3 -m pip install python-docx`

## Start 
1. Place `HeadingExporter.py` in a local folder, such as your Python virtual environment: `~/py_envs/scripts`.
2. Enable your virtual Python environment: `source ~/py_envs/bin/activate`
3. Browse to the path: `cd py_envs/scripts`
4. Start HeadingExporter: `python3 headingexporter.py example.docx headings.txt`

## Example Output
```
1 Introduction
    1.1 Background
        1.1.1 Details
```