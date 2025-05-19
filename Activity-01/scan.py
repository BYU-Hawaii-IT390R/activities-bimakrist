from pathlib import Path
import argparse

def scan_txt_files(directory, min_size_kb=None):
    directory = Path(directory)
    if not directory.exists():
        print("Directory does not exist.")
        return

    txt_files = list(directory.rglob("*.txt"))

    print(f"\nScanning: {directory.resolve()}")
    print(f"Found {len(txt_files)} text files:\n")

    print(f"{'File':<40} {'Size (KB)':>10}")
    print("-" * 52)

    total_size = 0
    folder_summary = {}  # Dictionary to hold folder stats

    for file in txt_files:
        rel_path = file.relative_to(directory)
        folder_path = file.parent.relative_to(directory)
        size_kb = file.stat().st_size / 1024

        if min_size_kb is not None and size_kb < min_size_kb:
            continue  # Skip small files

        # Add to folder summary
        if folder_path not in folder_summary:
            folder_summary[folder_path] = {"count": 0, "size": 0}

        folder_summary[folder_path]["count"] += 1
        folder_summary[folder_path]["size"] += size_kb
        total_size += size_kb

        print(f"{str(rel_path):<40} {size_kb:>10.1f}")

    print("-" * 52)
    print(f"Total size: {total_size:.1f} KB\n")

    # Print folder summary
    print("Summary:")
    for folder in sorted(folder_summary):
        count = folder_summary[folder]["count"]
        size = folder_summary[folder]["size"]
        print(f"  {folder}/{' ' * (15 - len(str(folder)))}—   {count:>2} files, {size:>5.1f} KB")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Recursively scan directory for .txt files.")
    parser.add_argument("path", help="Path to directory to scan")
    parser.add_argument("--min-size", type=float, dest="min_size_kb", help="Minimum file size in KB to include in results")
    args = parser.parse_args()
    
    scan_txt_files(args.path, args.min_size_kb)