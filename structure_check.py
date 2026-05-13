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

EXCLUDE_EXTENSIONS = {
    '.pyc',
    '.log',
    '.tmp'
}

OUTPUT_FILE = 'structure.txt'


def should_skip_file(file):
    return any(file.endswith(ext) for ext in EXCLUDE_EXTENSIONS)


def write_tree(startpath, file):
    for root, dirs, files in os.walk(startpath):

        # remove excluded folders
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]

        level = root.replace(startpath, '').count(os.sep)

        # LIMIT DEPTH (important)
        if level > 2:
            continue

        indent = '│   ' * level
        folder_name = os.path.basename(root)

        file.write(f'{indent}├── {folder_name}/\n')

        subindent = '│   ' * (level + 1)

        # only important files
        important_files = [
            f for f in files
            if not should_skip_file(f)
            and (
                f.endswith('.py')
                or f.endswith('.ipynb')
                or f.endswith('.csv')
                or f.endswith('.txt')
                or f.endswith('.md')
                or f.endswith('.pkl')
                or f == 'requirements.txt'
            )
        ]

        for f_name in important_files:
            file.write(f'{subindent}├── {f_name}\n')


with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
    write_tree('.', f)

print(f"Clean structure saved to {OUTPUT_FILE}")