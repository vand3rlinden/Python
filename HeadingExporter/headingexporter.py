import argparse
from docx import Document

def extract_headings_with_numbers(docx_file, output_txt_file):
    try:
        # Load the .docx file
        doc = Document(docx_file)

        # To track numbering for each heading level
        numbering = {}

        # Open the output file
        with open(output_txt_file, 'w', encoding='utf-8') as txt_file:
            # Iterate over the paragraphs in the document
            for para in doc.paragraphs:
                # Check if the paragraph is a heading
                if para.style.name.startswith('Heading'):
                    # Determine the heading level
                    level = int(para.style.name.replace('Heading ', ''))
                    
                    # Update numbering for the current level
                    numbering[level] = numbering.get(level, 0) + 1
                    
                    # Reset numbering for deeper levels
                    for deeper_level in range(level + 1, 10):
                        if deeper_level in numbering:
                            del numbering[deeper_level]
                    
                    # Generate the heading number as a string (e.g., "1.1.1")
                    heading_number = '.'.join(str(numbering[i]) for i in sorted(numbering) if i <= level)
                    
                    # Write the numbered heading with appropriate indentation
                    txt_file.write(f"{' ' * (level - 1) * 4}{heading_number} {para.text}\n")
        
        print(f"\033[32mHeadings successfully extracted to:\033[0m {output_txt_file}")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    # Set up argument parsing
    parser = argparse.ArgumentParser(description="Extract headings from a .docx file and save to a .txt file with numbers.")
    parser.add_argument("docx_file", help="Path to the input .docx file")
    parser.add_argument("output_txt_file", help="Path to the output .txt file")
    
    # Parse the arguments
    args = parser.parse_args()
    
    # Call the function with the provided arguments
    extract_headings_with_numbers(args.docx_file, args.output_txt_file)
