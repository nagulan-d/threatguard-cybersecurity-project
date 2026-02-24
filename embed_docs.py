#!/usr/bin/env python3
"""
Script to embed full documentation content into PROJECT_MASTER_REFERENCE.md
"""

import os

# Define the documentation files and their content markers
DOC_FILES = {
    'THREAT_PROCESSOR_DOCS.md': 'TOPIC GROUP 3',
    'AUTO_BLOCKING_GUIDE.md': 'TOPIC GROUP 4',
    'REALTIME_AUTO_BLOCKER_GUIDE.md': 'TOPIC GROUP 4',
    'IP_BLOCKING_SYNC_IMPLEMENTATION.md': 'TOPIC GROUP 4',
    'EMAIL_BLOCKING_ARCHITECTURE.md': 'TOPIC GROUP 5',
    'NOTIFICATION_SETTINGS.md': 'TOPIC GROUP 5',
    'TESTING_SUMMARY.md': 'TOPIC GROUP 6',
    'ADMIN_DASHBOARD_IMPLEMENTATION.md': 'TOPIC GROUP 7',
    'QUICK_START.md': 'TOPIC GROUP 8',
    'DOCUMENTATION_INDEX.md': 'TOPIC GROUP 8',
    'DEPLOYMENT_GUIDE.md': 'TOPIC GROUP 2'
}

def read_file_content(filename):
    """Read full content of a documentation file"""
    filepath = os.path.join('c:\\Users\\nagul\\Downloads\\Final_Project\\readme', filename)
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        return content
    except Exception as e:
        print(f"Error reading {filename}: {e}")
        return f"[Error: Could not read {filename}]"

def main():
    master_ref_path = 'c:\\Users\\nagul\\Downloads\\Final_Project\\readme\\PROJECT_MASTER_REFERENCE.md'
    
    # Read the master reference
    with open(master_ref_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Replace each placeholder
    for doc_file in DOC_FILES.keys():
        placeholder = f"[Full contents of {doc_file} as read earlier"
        
        if placeholder in content:
            doc_content = read_file_content(doc_file)
            
            # Find and replace the placeholder line
            lines = content.split('\n')
            new_lines = []
            
            for line in lines:
                if placeholder in line:
                    # Replace with actual content wrapped in proper formatting
                    new_lines.append(f"\n````markdown\n{doc_content}\n````\n")
                else:
                    new_lines.append(line)
            
            content = '\n'.join(new_lines)
            print(f"✓ Embedded: {doc_file}")
    
    # Write back
    with open(master_ref_path, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"\n✅ All documentation embedded into PROJECT_MASTER_REFERENCE.md")
    print(f"📊 Final file size: {len(content):,} characters")

if __name__ == '__main__':
    main()
