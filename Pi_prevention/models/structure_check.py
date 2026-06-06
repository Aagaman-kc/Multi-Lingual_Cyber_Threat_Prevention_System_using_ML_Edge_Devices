import os

# folders/files to ignore
EXCLUDE_DIRS = {
    'venv',
    '__pycache__',
    '.git',
    '.idea',
    '.vscode',
    'node_modules',
    'build',
    'dist',
    '.pytest_cache',
    'env'
}

# file types to ignore completely
EXCLUDE_EXTENSIONS = {
    '.pyc',
    '.log',
    '.tmp'
}

# IMPORTANT: file types to SHOW (expanded)
INCLUDE_EXTENSIONS = {
    '.py',
    '.ipynb',
    '.csv',
    '.txt',
    '.md',
    '.pkl',

    # 🖼️ images / plots
    '.png',
    '.jpg',
    '.jpeg',
    '.svg',
    '.webp',

    # optional (plots often stored like this)
    '.pdf'
}

OUTPUT_FILE = 'structure.txt'


def should_skip_file(file):
    return any(file.endswith(ext) for ext in EXCLUDE_EXTENSIONS)


def is_important_file(file):
    return (
        file in {'requirements.txt'} or
        any(file.endswith(ext) for ext in INCLUDE_EXTENSIONS)
    )


def write_tree(startpath, file):
    for root, dirs, files in os.walk(startpath):

        # remove unwanted folders
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]

        level = root.replace(startpath, '').count(os.sep)

        # depth limit
        if level > 3:
            continue

        indent = '│   ' * level
        folder_name = os.path.basename(root)

        file.write(f'{indent}├── {folder_name}/\n')

        subindent = '│   ' * (level + 1)

        # filter important files INCLUDING images/plots
        important_files = [
            f for f in files
            if not should_skip_file(f) and is_important_file(f)
        ]

        # sort for cleaner output (images last or alphabetical)
        important_files.sort()

        for f_name in important_files:
            # small visual marker for plots/images
            if f_name.endswith(('.png', '.jpg', '.jpeg', '.svg', '.webp')):
                file.write(f'{subindent}🖼 {f_name}\n')
            else:
                file.write(f'{subindent}├── {f_name}\n')


with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
    write_tree('.', f)

print(f"✅ Clean structure saved to {OUTPUT_FILE}")