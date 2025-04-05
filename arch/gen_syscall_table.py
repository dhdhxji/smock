import argparse
    
parser = argparse.ArgumentParser()
parser.add_argument('tbl_path')

args = parser.parse_args()

with open(args.tbl_path) as tbl:
    tbl_content = tbl.read()

    # Strip out comments
    tbl_content = filter(lambda line: not line.startswith('#') and line, tbl_content.split('\n'))
    tbl_content = map(str.split, tbl_content)
    
    syscall_metadata = map(
        lambda s: f'[{s[0]:3}] = (syscall_def){{.name = "{s[2]}"}},',
        tbl_content)

    syscall_metadata = map(
        lambda s: f'    {s:74}\\',
        syscall_metadata)

    print(f'#define SMOCK_ARCH_SYSCALL_TABLE \\')
    syscall_metadata = '\n'.join(syscall_metadata)
    print(syscall_metadata)
    print()

