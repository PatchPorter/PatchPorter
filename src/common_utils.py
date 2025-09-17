import subprocess
from config import temp_path, log_file_path

def run_command(command, path=None):
    result = subprocess.run(command, cwd=path, shell=True, capture_output=True, text=True, errors='ignore')
    return result

def get_nearest_commit_id(commit, commit_list, path):
    # commit_list [3, 2, 1]
    for i in range(len(commit_list)):
        if is_commit1_earlier_than_commit2(commit_list[i], commit, path):
            return i

def is_commit1_earlier_than_commit2(commit1, commit2, path):
    if commit1 == commit2 or commit1 in commit2 or commit2 in commit1:
        return True
    result = run_command(f"git rev-list {commit1}..{commit2}", path=path).stdout
    if result.strip():
        return True
    return False

def remove_duplicate_lines(file_path):
    unique_lines = set()
    with open(file_path, 'r') as file:
        for line in file:
            unique_lines.add(line)
    with open(file_path, 'w') as file:
        for line in unique_lines:
            file.write(line)

def temp_print(*args):
    # if not hasattr(temp_print, "has_run"):
    #     with open('./data/temp.txt', 'w') as f:
    #         ...
    #     temp_print.has_run = True
    with open(temp_path, 'a') as f:
        for i in args:
            print(i, file=f)
        print('-----------\n\n', file=f)

def checkout_commit(commit, path):
    err = run_command(f"git checkout -f {commit} && git clean -df ", path).stderr
    if 'fatal' in err or 'error' in err:
        run_command(f"git fetch origin {commit}", path)
        run_command(f"git checkout -f {commit} && git clean -df ", path)
    # if commit != '.':
    #     run_command('npm install --registry=https://registry.npmmirror.com', path=path)
    return err

def read_file(file_path):
    with open(file_path) as f:
        return f.read()
    
def read_lines_file(file_path):
    with open(file_path) as f:
        return f.readlines()
    
def get_parent_commit_local(commit_id, path):
    return run_command(f'git log -1 --pretty=%P {commit_id}', path=path).stdout.strip().split(' ')[0]

def sort_commit_list(head_commit, commit_list, path):
    result = run_command(f'git rev-list {head_commit}', path=path)
    topological_order = result.stdout.strip().split("\n")
    commit_order = {commit: i for i, commit in enumerate(topological_order)}
    sorted_commits = sorted(commit_list, key=lambda commit: commit_order.get(commit, float('inf')))
    return sorted_commits

def parse_localization_info(file_path):
    commit_lines = {}
    with open(file_path) as f:
        localization_info = [i.strip() for i in f.readlines()]
    for line in localization_info:
        commit_id, linos, index = line.split('##')
        linos = eval(linos)
        if commit_id in commit_lines:
            commit_lines[commit_id][index] = linos
        else: commit_lines[commit_id] = {index: linos}
    return commit_lines

def count_file_lines(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()
        return len(lines)

def get_linos(line_content, file_path):
    linos = []
    with open(file_path, 'r') as file:
        lines = file.readlines()
        for i, line in enumerate(lines):
            if line_content in line:
                linos.append(i+1)
    return linos
