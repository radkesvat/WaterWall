"""Package final Waterwall executables while keeping CI diagnostics out of releases."""
import argparse
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


def package_release_artifacts(artifacts, output):
    output.mkdir(parents=True, exist_ok=True)
    count = 0
    for directory in sorted(artifacts.glob('Waterwall-*')):
        if not directory.is_dir() or directory.name.endswith('-diagnostics'):
            continue
        executables = [directory/name for name in ['Waterwall', 'Waterwall.exe']
                       if (directory/name).is_file()]
        if not executables:
            raise ValueError(f'No final Waterwall executable in {directory}')
        with ZipFile(output/(directory.name + '.zip'), 'w', compression=ZIP_DEFLATED) as archive:
            for executable in executables:
                archive.write(executable, arcname=executable.name)
        count += 1
    if count == 0:
        raise ValueError('No release executables were downloaded')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('artifacts', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    package_release_artifacts(args.artifacts, args.output)
