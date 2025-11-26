import subprocess
import os
import unidiff
from Levenshtein import distance
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor
import json

root_path = '/data2/backport-repo'
loaded_path = './merged-data.csv'
output_path = './content_compare.json'
key_word = ['port', 'cherrypick', 'cherry-pick', 'backport', 'porting']

def run_command(command, path=None):
    result = subprocess.run(command, cwd=path, shell=True, capture_output=True, text=True, errors='ignore')
    return result

def merge_data(file_path_list):
    def read_csv_files(file_paths):
        cve_data = defaultdict(set)
        for file_path in file_paths:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    parts = [part.strip() for part in line.split(',')]
                    cve = parts[0]
                    links = parts[1:]
                    cve_data[cve].update(link for link in links if link)
        return cve_data
    cve_data = read_csv_files(file_path_list)
    output_file = './merged-data.csv'
    with open(output_file, 'w') as f:
        for cve in sorted(cve_data.keys()):
            links = sorted(cve_data[cve])
            line = f"{cve},{','.join(links)}\n"
            f.write(line)


def clone_repo(repo):
    print(f'git clone {repo.replace('github.com', 'githubfast.com')}')
    run_command(f'GIT_TERMINAL_PROMPT=0 git clone {repo.replace('github.com', 'githubfast.com')}', path=root_path)
    repo_path = os.path.join(root_path, repo[repo.rfind('/')+1:])
    return repo_path

def load_data():
    with open(loaded_path, 'r') as f:
        lines = f.readlines()
    return lines

def uniform_patch(patch_id):
    if '...' in patch_id:
        return None
    return patch_id[:patch_id.rfind('#')]

def get_repo_from_patch(patch_id):
    repo_id = patch_id[:patch_id.rfind('/commit')]
    return repo_id

def list_commits(repo_path):
    repo_name = repo_path[repo_path.rfind('/')+1:]
    pwd = '/data2/backport-repo/commit_lines'
    commit_path = os.path.join(pwd, repo_name)
    try:
        with open(commit_path, 'r', errors='ignore') as f:
            commits = [i.strip() for i in f.readlines()]
    except FileNotFoundError:
        commits = []
    if commits:
        return commits
    commits = run_command('git log --all --oneline', path=repo_path).stdout
    lines = [i[:i.find(' ')] for i in commits.split('\n')][:-1]
    with open(commit_path, 'w') as f:
        for i in lines:
            print(i, file=f)
    return lines

def get_commit_content(commit_id, repo_path):
    try:
        commit_content = run_command(f'git show {commit_id}', path=repo_path).stdout
        current_patch = unidiff.PatchSet.from_string(commit_content)
    except:
        return None
    hunks = []
    for patch in current_patch:
        if 'min.js' in patch.path or 'test' in patch.path or '.json' in patch.path or ('.js' not in patch.path) or patch.is_added_file:
            continue
        for hunk in patch:
            add = ''
            delete = ''
            similarity = 0
            for line in hunk:
                if line.value.strip() == '':
                    continue
                if line.is_removed:
                    delete += f'{str(line)}'
                if line.is_added:
                    add += f'{str(line)}'
            hunks.append([delete, add, similarity])
    return hunks

def iterate_repo(cve_id, repo_path, patch_id, patch_url):
    print(repo_path)
    commits = list_commits(repo_path)
    print(f'{cve_id}-{repo_path} message comparing ')
    patch_message = run_command(f'git show -s --format=%B {patch_id}', path=repo_path).stdout
    for commit in commits:
        if commit in patch_id:
            continue
        LLM_compare()
        message_result = message_compare(commit, patch_id, cve_id, repo_path, patch_url, patch_message)
        content_compare(commit, repo_path, patch_url, patch_id, cve_id, message_result)

def json_add(file_path, new_data):
    existing_data = []
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        existing_data = []
    else:
        with open(file_path, "r", encoding="utf-8") as f:
            existing_data = json.load(f)
    if isinstance(existing_data, list):
        existing_data.append(new_data)
    else:
        existing_data = [existing_data, new_data]
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(existing_data, f, indent=4, ensure_ascii=False)

def message_compare(commit, patch_id, cve_id, repo_path, patch_url, patch_message):
    message = run_command(f'git show -s --format=%B {commit}', path=repo_path).stdout

    if (patch_id in message or cve_id in message) and 'revert' not in message.lower() and 'merge' not in message.lower():
        return True
    if 1 - distance(message, patch_message)/max(len(message), len(patch_message)) > 0.96:
        return True
    return False

def is_merged_commit(commit1, commit2, repo_path):
    result1 = run_command(f"git rev-list {commit1}..{commit2}", path=repo_path).stdout
    result2 = run_command(f"git rev-list {commit2}..{commit1}", path=repo_path).stdout
    if result1.strip() and result2.strip():
        return False
    return True

def get_similarity_result(commit1, commit2, repo_path, message_result):
    threshold = 0.5
    threshold_exact = 0.96
    current_content = get_commit_content(commit1, repo_path)
    patch_content = get_commit_content(commit2, repo_path)
    if len(patch_content) == 0 or len(current_content) == 0:
        return False
    if current_content is None or patch_content is None:
        return False
    for hunk in current_content:
        for patch_hunk in patch_content:
            similarity = 1 - (distance(hunk[0], patch_hunk[0]) + distance(hunk[1], patch_hunk[1])) / (max(len(hunk[0]), len(patch_hunk[0])) + max(len(hunk[1]), len(patch_hunk[1])))
            if similarity > hunk[-1]:
                hunk[-1] = similarity
            if similarity > patch_hunk[-1]:
                patch_hunk[-1] = similarity
    if (len([i for i in current_content if i[-1] > threshold]) == len(current_content) or len([i for i in patch_content if i[-1] > threshold]) == len(patch_content)) and abs(len(current_content)-len(patch_content)) <= 3 and message_result:
        return True
    if len([i for i in current_content if i[-1] > threshold_exact]) == len(current_content) or len([i for i in patch_content if i[-1] > threshold_exact]) == len(patch_content):
        return True
    return False


def content_compare(commit, repo_path, patch_url, patch_id, cve_id, message_result):
    similarity_result = get_similarity_result(commit, patch_id, repo_path, message_result)
    if similarity_result:
        records = {
            'cve_id': cve_id,
            'patch_id': patch_id,
            'repo_path': repo_path,
            'commit_id': commit,
            'patch_url': patch_url,
            'commit_url': f'{patch_url.replace(patch_id, commit)}'
        }
        json_add(output_path, records)

def LLM_compare():
    ...


def iterate(line):
    parts = line.strip().split(',')
    cve_id, patch_url = parts[0], parts[-1]
    patch_url = uniform_patch(patch_url)
    if patch_url is None:
        return
    repo = patch_url[:patch_url.rfind('/commit')]
    patch_id = patch_url[patch_url.rfind('/')+1:]
    repo_path = clone_repo(repo)
    if 'linux' in repo_path:
        return
    iterate_repo(cve_id, repo_path, patch_id, patch_url)

def process_content_json():
    with open('./content_compare.json') as f:
        content_compare_data = json.load(f)
    final_cve_list = []
    sign_list = []
    for cve_item in content_compare_data:
        if cve_item['cve_id']+cve_item['commit_url'] in sign_list:
            continue
        sign_list.append(cve_item['cve_id']+cve_item['commit_url'])
        final_cve_list.append(cve_item)
    with open('./content_compare.bk.json', 'w') as f:
        json.dump(final_cve_list, f, indent=4, ensure_ascii=False)

def main():
    lines = load_data()
    for line in lines:
        iterate(line)

def main_multiprocess():
    lines = load_data()
    coped_cves = []
    lines = [i for i in lines if i.split(',')[0] not in coped_cves]
    with ProcessPoolExecutor(max_workers=64) as executor:
        futures = [executor.submit(iterate, line) for line in lines]

if __name__ == '__main__':
    main_multiprocess()
