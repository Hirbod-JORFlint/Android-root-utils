import sys
import re

def parse_getprop_file(filepath):
    """Parses a getprop output file into a dictionary."""
    props = {}
    # Regex to extract key and value from the [key]: [value] format
    pattern = re.compile(r'^\[(.*?)\]:\s*\[(.*?)\]$')
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                match = pattern.match(line)
                if match:
                    key = match.group(1)
                    value = match.group(2)
                    props[key] = value
    except FileNotFoundError:
        print(f"Error: The file '{filepath}' was not found.")
        sys.exit(1)
        
    return props

def compare_props(file1_path, file2_path):
    """Compares two parsed getprop dictionaries and prints the differences."""
    props1 = parse_getprop_file(file1_path)
    props2 = parse_getprop_file(file2_path)
    
    missing_in_file2 = []
    missing_in_file1 = []
    changed_props = []
    
    # Check for missing in file 2 and changed properties
    for key, value1 in props1.items():
        if key not in props2:
            missing_in_file2.append((key, value1))
        elif props2[key] != value1:
            changed_props.append((key, value1, props2[key]))
            
    # Check for missing in file 1
    for key, value2 in props2.items():
        if key not in props1:
            missing_in_file1.append((key, value2))
            
    # Output formatting
    print(f"==================================================")
    print(f" Comparing: '{file1_path}' vs '{file2_path}'")
    print(f"==================================================\n")
    
    print("### 1. Properties Missing in Second File ###")
    if missing_in_file2:
        for key, val in sorted(missing_in_file2):
            print(f"[-] {key}")
            print(f"    Was: {val}")
    else:
        print("    None. No properties from the first file are missing in the second.")

    print("\n### 2. Properties Missing in First File ###")
    if missing_in_file1:
        for key, val in sorted(missing_in_file1):
            print(f"[+] {key}")
            print(f"    New: {val}")
    else:
        print("    None. No properties from the second file are missing in the first.")
        
    print("\n### 3. Properties with Changed Values ###")
    if changed_props:
        for key, val1, val2 in sorted(changed_props):
            print(f"[*] {key}")
            print(f"    Old Rom : {val1}")
            print(f"    New Rom : {val2}")
    else:
        print("    None. All shared properties have identical values.")

if __name__ == "__main__":
    # Ensure the user provided two files as arguments
    if len(sys.argv) != 3:
        print("Usage: python compare_props.py <old_rom_props.txt> <new_rom_props.txt>")
    else:
        compare_props(sys.argv[1], sys.argv[2])
