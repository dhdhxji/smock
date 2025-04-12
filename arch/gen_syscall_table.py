import argparse
from textwrap import dedent
    
parser = argparse.ArgumentParser()
parser.add_argument('tbl_path')

args = parser.parse_args()

def syscall_entry(syscall: tuple) -> str:
    (number, _, name, *_) = syscall
    return dedent(f'''\
    [{number:3}] = {{
        .name = "{name}",
        .args = (syscall_arg_def[]) {{
            {{ 0 }}
        }},
        .ret = {{ 0 }}
    }}''')

def format_header(data: str) -> str:
    lines = data.splitlines()
    lines = (line.rstrip() for line in lines)
    lines = (f'    {line:76}\\' for line in lines)
    return '\n'.join(lines)

with open(args.tbl_path) as tbl:
    tbl_content = tbl.read()

    # Strip out comments
    tbl_content = filter(lambda line: not line.startswith('#') and line, tbl_content.split('\n'))
    tbl_content = map(str.split, tbl_content)

    syscall_info = map(syscall_entry, tbl_content)
    syscall_info = ',\n'.join(syscall_info)
    syscall_info = format_header(syscall_info)

    print(f'#define SMOCK_ARCH_SYSCALL_TABLE \\')
    print(syscall_info)
    print()

