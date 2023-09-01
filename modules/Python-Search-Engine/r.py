import re
from pathlib import Path

# Open the file and read its contents
file_path = Path('gift_cards_site.txt')
with file_path.open(mode='r', encoding='utf-8') as file:
    text = file.read()

pattern = r"(https?://[^/ ]+)"

matches = re.findall(pattern, text)
if matches:
    for match in matches:
        print(match)
else:
    print("No matches found.")