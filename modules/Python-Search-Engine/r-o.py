import re
from pathlib import Path

# Open the file and read its contents
file_path = Path('http_out.txt')
with file_path.open(mode='r', encoding='utf-8',errors='replace') as file:
    text = file.read()

pattern = r"(https?://[^/ ]+)"

matches = re.findall(pattern, text)
if matches:
    with open('output.txt', mode='w', encoding='utf-8') as output_file:
        for match in matches:
            output_file.write(match + '\n')
else:
    print("No matches found.")