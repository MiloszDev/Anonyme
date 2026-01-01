import logging

from pathlib import Path

logging.basicConfig(level=logging.INFO, format='[%(asctime)s]: %(message)s')

files = [
    ".github/workflows/.gitkeep",

    "interface/__init__.py",
    "interface/cli.py",
    "interface/service.py",

    "docs/README.md",
    
    "tests/.gitkeep",

]

for filepath in files:
    path = Path(filepath)
    directory = path.parent

    try:
        if not directory.exists():
            directory.mkdir(parents=True, exist_ok=True)
            logging.info(f'Created directory: {directory}')
        else:
            logging.info(f'Directory already exists: {directory}')

        if not path.exists():
            with open(path, 'w') as f:
                logging.info(f'Created file: {path}')
        else:
            logging.info(f'File already exists: {path}')
    except Exception as e:
        logging.error(f'Error creating {filepath}: {e}')