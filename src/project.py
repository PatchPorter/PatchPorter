import os
import re
import json

import requests
import unidiff
from config import github_token
import nltk
from nltk.translate.bleu_score import sentence_bleu, SmoothingFunction
from common_utils import run_command, checkout_commit, get_parent_commit_local, is_commit1_earlier_than_commit2
from codebleu import calc_codebleu


class Project:
    def __init__(self, prj_path):
        self.prj_path = prj_path
        self.prj_name, self.version = prj_path.split('/')[-1].split('_')
        self.prj_id = prj_path.split('/')[-1]
        self.pkgjson_path = os.path.join(prj_path, 'package.json')
        self.cve_id = self.get_cve_id()
        self.npm_path = os.path.join(self.prj_path, 'node_modules')
        self.npm_prj_path = os.path.join(self.npm_path, self.prj_name)

        self.patch_path = os.path.join(self.prj_path, 'patch.diff')
        self.final_patch_path = os.path.join(self.prj_path, 'final-patch.diff')
        self.patch_content = self.get_patch_content()
        self.unidiff_patch = self.get_unidiff_patch()
        self.patch_url = self.get_patch_url()
        self.patch_id = self.patch_url.split('/')[-1].split('#')[0]
        self.target_file_name = self.unidiff_patch[0].path.split('/')[-1]
        self.target_file_path = os.path.join(self.npm_prj_path, self.unidiff_patch[0].path)

        self.localization_info_path = os.path.join(self.prj_path, 'localization')
        run_command(f'mkdir -p {self.localization_info_path }', path=self.prj_path)
        self.version_map_path = os.path.join(self.prj_path, 'version-map.txt')
        self.vul_version_map_path = os.path.join(self.prj_path, 'vulnerable_versions.txt')
        self.vul_commit_version_map = self.get_version_map(self.vul_version_map_path)
        self.commit_version_map = self.get_version_map(self.version_map_path)

        self.result_path = os.path.join(self.prj_path, 'result')
        self.prompt_path = os.path.join(self.prj_path, 'prompt')
        self.output_path = os.path.join(self.prj_path, 'output-result')
        self.result_file_path = os.path.join(self.prj_path, 'result.txt')
        self.challenge_version_path = os.path.join(self.prj_path, 'challenge-version.txt')
        self.name_history_path = os.path.join(self.prj_path, 'name_history.json')
        self.load_name_history()
        
    def get_cve_id(self):
        with open(self.pkgjson_path) as f:
            pkgjson = json.load(f)
        return pkgjson.get('id')

    def get_oldest_vulnerable_version(self):
        with open(self.vul_version_map_path) as f:
            versions = [i.strip() for i in f.readlines()]
        return versions[-1].split(' ')[0]

    def get_challenge_version(self):
        with open(self.challenge_version_path) as f:
            return f.read().strip()

    def get_challenge_commit(self):
        version = self.get_challenge_version()
        return self.find_commit_from_version(version)


    # def get_challenge_version(self):
    #     # versions = list(self.vul_commit_version_map.values())
    #     with open(self.localization_info_path) as f:
    #         localization_info = f.read()
    #     with open(self.vul_version_map_path) as f:
    #         versions = [i.strip() for i in f.readlines()][::-1]
    #     for i in versions:
    #         commit_id, version = i.split(' ')
    #         if commit_id in localization_info:
    #             return version

    def get_responding_file_name(self, commit_id):
        if commit_id.strip() == '':
            return None
        patch_file_content = run_command(f'git show {self.patch_id}:{self.unidiff_patch[0].path}', path=self.npm_prj_path).stdout
        commit_file_list = run_command(f"git ls-tree -r --name-only {commit_id}", path=self.npm_prj_path).stdout.splitlines()
        commit_js_file = [i for i in commit_file_list if i.endswith('.js') and 'test' not in i and 'dist' not in i and 'min.js' not in i and '.history' not in i]
        # print(self.unidiff_patch[0].path)
        # if self.unidiff_patch[0].path in commit_js_file:
        #     return self.unidiff_patch[0].path
        if len(commit_js_file) == 0:
            return None
        if len(commit_js_file) == 1:
            return commit_js_file[0]
        commit_file_content_list = [run_command(f'git show {commit_id}:{i}', path=self.npm_prj_path).stdout for i in commit_js_file]
        # print(commit_file_content_list)
        # print(commit_file_content_list)
        # similarity_list = [codebleu(i, patch_file_content, 'javascript') for i in commit_file_content_list]
        similarity_list = [calculate_bleu(i, patch_file_content) for i in commit_file_content_list]
        # print(commit_js_file)
        # print(similarity_list)
        # print(similarity_list)
        target_index = similarity_list.index(max(similarity_list))
        return commit_js_file[target_index]

    # def get_responding_file_name(self, commit_id):
    #     for i in self.name_history:
    #         if is_commit1_earlier_than_commit2(i[0], commit_id, path=self.npm_prj_path):
    #             return i[1]

    def load_name_history(self):
        self.name_history = [tuple(i) for i in self.read_name_history()]
        if len(self.name_history) == 0:
            self.name_history = self.get_target_name_history(self.unidiff_patch[0].path)
            self.write_name_history()

    def read_name_history(self):
        with open(self.name_history_path, "w") as file:
            json.dump([], file)
            return []
        # try:
        #     with open(self.name_history_path, "r") as file:
        #         return [tuple(i) for i in json.load(file)]
        # except:
        #     with open(self.name_history_path, "w") as file:
        #         json.dump([], file)
        #     return []

    def write_name_history(self):
        temp_name_history = self.read_name_history()
        if len(temp_name_history) < len(self.name_history):
            with open(self.name_history_path, "w") as file:
                json.dump(self.name_history, file)

    def get_target_name_history(self, target_file_path):
        log_output = run_command(f'git log {self.patch_id} --follow --name-status --pretty=format:%H -- {target_file_path}', path=self.npm_prj_path).stdout
        reverse_log_output = run_command(f'git log {self.patch_id} --reverse --follow --name-status --pretty=format:%H -- {target_file_path}', path=self.npm_prj_path).stdout
        rename_history = []
        commit_hash = None
        for line in log_output.splitlines():
            if re.match(r'^[0-9a-f]{40}$', line):
                commit_hash = line
            elif commit_hash and (line.startswith("R") or line.startswith("C")):
                _, old_file, new_file = line.split("\t")
                rename_history.append((commit_hash, new_file))
                commit_hash = None
            elif commit_hash and line.startswith("A"):
                _, new_file = line.split("\t")
                rename_history.append((commit_hash, new_file))
                commit_hash = None
        return rename_history

    def get_target_file_content_commit(self, commit):
        file_content = run_command(f'git show {commit}:{self.get_responding_file_name(commit)}', path=self.npm_prj_path).stdout
        if file_content[-1] == '\n':
            file_content = file_content.splitlines() + ['']
        else:
            file_content = file_content.splitlines()
        return [i+'\n' for i in file_content]

    def get_target_file_content_commit_all(self, commit):
        return run_command(f'git show {commit}:{self.get_responding_file_name(commit)}', path=self.npm_prj_path).stdout

    def get_target_file_content(self):
        try:
            with open(self.target_file_path) as f:
                target_file_content = f.read()
        except:
            return None
        target_file_length = get_loc(self.target_file_path)
        return target_file_content, target_file_length

    def checkout(self, patch_id):
        return checkout_commit(patch_id, self.npm_prj_path)

    def jest(self):
        syntax_error_list = ['Jest failed to parse a file', 'not defined', 'is not a function', 'is not a constructor']
        result = run_command(f'timeout 40s jest --testPathIgnorePatterns="node_modules" --forceExit', path=self.prj_path).stderr
        if 'Received' in result and 'Expected' in result: return 'True'
        elif 'PASS' in result: return 'False#0'
        elif any(i in result for i in syntax_error_list): return 'False#1'
        return 'Check'

        if 'Cannot find module' in result:
            with open('./temp.txt', 'a') as f:
                print(self.prj_path, file=f)
        if 'Expected: not undefined' in result: return 'True'
        elif 'while waiting for `done()` to be called' in result: return 'True'
        elif 'PASS' in result: return 'False#0'
        # elif 'Received' not in result or 'Expected' not in result: return 'False#4'
        elif 'Jest failed to parse a file' in result: return 'False#1'
        elif 'not defined' in result or (' undefined' in result and 'Received: undefined' not in result) or 'is not a function' in result or 'is not a constructor' in result: return 'False#2'
        # elif 'to be called but received' in result: return 'False#3'
        elif 'FAIL' in result: return 'True'
        else: return False

    def checkout_patch(self):
        return checkout_commit(self.patch_id, self.npm_prj_path)

    def checkout_before_patch(self):
        parent_commit_id = get_parent_commit_local(self.patch_id, self.npm_prj_path)
        return checkout_commit(parent_commit_id, self.npm_prj_path)

    # def get_vul_commit_version_map(self):
    #     with open(self.vul_version_map_path) as f:
    #         lines = [i.strip() for i in f.readlines()]
    #     vul_commit_version_map = {}
    #     for line in lines:
    #         commit_id, version = line.split(' ')
    #         vul_commit_version_map[commit_id] = version
    #     return vul_commit_version_map

    def get_version_map(self, version_path):
        with open(version_path) as f:
            lines = [i.strip() for i in f.readlines()]
        commit_version_map = {}
        for line in lines:
            commit_id, version = line.split(' ')
            commit_version_map[commit_id] = version
        return commit_version_map

    def get_vulnerable_versions_count(self):
        return len(self.vul_commit_version_map)

    def find_commit_from_version(self, version):
        for c, v in self.commit_version_map.items():
            if version == v:
                return c
            
    def find_version_from_commit(self, commit):
        for c, v in self.commit_version_map.items():
            if commit == c:
                return v

    def bk_modules(self):
        run_command(f"cp -r node_modules node_modules_bk", path=self.prj_path)

    def rm_modules(self):
        run_command(f"rm -rf node_modules", path=self.prj_path)

    def back_modules(self):
        run_command(f"rm -rf node_modules && cp -r node_modules_bk node_modules", path=self.prj_path)

    def bk_pkg_json(self):
        if not os.path.exists(os.path.join(self.prj_path, 'package.json.bk')):
            run_command('cp ./package.json ./package.json.bk', path=self.prj_path)

    def cp_out(self):
        run_command(f"cp {self.target_file_path} {os.path.join(self.prj_path, self.target_file_name)}")

    def cp_in(self):
        run_command(f"cp {os.path.join(self.prj_path, self.target_file_name)} {self.target_file_path}")

    def get_patch_url(self):
        with open(self.pkgjson_path) as f:
            patch_url = json.load(f)['fixCommit']
        return convert_github_pr_commit_url(patch_url)

    def get_unidiff_patch(self):
        with open(self.final_patch_path) as f:
            patch_content = f.read()
        current_patch = unidiff.PatchSet.from_string(patch_content)
        patches = []
        for patch in current_patch:
            patches.append(patch)
        return patches
    
    def get_patch_content(self):
        with open(self.final_patch_path) as f:
            patch_content = f.read()
        return patch_content

    def chmod_prompt_path(self):
        chmod(self.prompt_path)

    def get_hunks(self):
        hunks = []
        for patch in self.unidiff_patch:
            for hunk in patch:
                hunks.append(hunk)
        return hunks
    
    def split_hunks_into_continuous_changes(self):
        result = []
        for patched_file in self.unidiff_patch:
            for original_hunk in patched_file:
                blocks = split_into_blocks(original_hunk)
                # for block in blocks:
                #     new_hunk = create_new_hunk(original_hunk, block)
                #     result.append(new_hunk)
                for block in blocks:
                    result.append(''.join([i.line_type+i.value for i in block]))
        return result

    def get_continuous_hunk_content(self):
        modifications = []
        for patched_file in self.unidiff_patch:
            for hunk in patched_file:
                current_chunk = []
                for line in hunk:
                    if 'No newline at end of file' in line.value:
                        continue
                    if line.is_removed or line.is_added:
                        current_chunk.append(line.line_type+line.value)
                    else:
                        if current_chunk:
                            modifications.append(''.join(current_chunk))
                        current_chunk = []
                if current_chunk:
                    modifications.append(''.join(current_chunk))
                    current_chunk = []
        return modifications


def split_into_blocks(hunk):
    t = [' '] if hunk[0].line_type == ' ' else ['-', '+']
    blocks = []
    current_block = []
    result_blocks = []
    for line in hunk:
        if line.line_type not in t:
            blocks.append(current_block)
            current_block = [line]
            t = [' '] if line.line_type == ' ' else ['-', '+']
        else: current_block.append(line)
    blocks.append(current_block)
    # for i in blocks:
    #     print('***\n')
    #     print(i)
    #     print('***\n')
    for index, block in enumerate(blocks):
        if block[0].line_type in ('-', '+'):
            result = []
            result.extend(blocks[index-1]) if index-1 >= 0 else None
            result.extend(block)
            result.extend(blocks[index+1]) if index+1 < len(blocks) else None
            result_blocks.append(result)
    return result_blocks


# def split_into_blocks(hunk):
#     blocks = []
#     current_block = []
#     for line in hunk:
#         if line.line_type in ('-', '+'):
#             current_block.append(line)
#         else:
#             if current_block:
#                 blocks.append(current_block)
#                 current_block = []
#     if current_block:
#         blocks.append(current_block)
#     return blocks

def create_new_hunk(original_hunk, block):
    new_lines = []
    block_lines = [(line.line_type, line.value, get_source_line_no(line), get_target_line_no(line)) for line in block]
    for line in original_hunk:
        if line.line_type != '+' or (line.line_type, line.value, get_source_line_no(line), get_target_line_no(line)) in block_lines:
            if line.line_type == '-':
                if (line.line_type, line.value, get_source_line_no(line), get_target_line_no(line)) in block_lines:
                    new_lines.append(f"-{line.value}")
                else: new_lines.append(f" {line.value}")
            elif line.line_type == '+':
                new_lines.append(f"+{line.value}")
            else:
                new_lines.append(f" {line.value}")
    if not new_lines:
        return None
    return ''.join(new_lines)


def codebleu(contentA, contentB, language):
    result = calc_codebleu(
        references=[contentA],
        predictions=[contentB],
        lang=language,
        weights=(0.25, 0.25, 0.25, 0.25)
    )
    return result['codebleu']

def get_source_line_no(line):
    return line.source_line_no if line.line_type in ('-', ' ') else None

def get_target_line_no(line):
    return line.target_line_no if line.line_type in ('+', ' ') else None

def get_parent_commit(patch_url):
    patch_url = patch_url.replace('github', 'api.github').replace('.com', '.com/repos').replace('commit', 'commits')
    headers = {
        "Authorization": f"token {github_token}"
    }
    response = requests.get(patch_url, headers=headers)
    return response.json()['parents'][0]['sha']

def get_loc(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()
        length = len(lines)
    return length

def convert_github_pr_commit_url(pr_commit_url):
    pattern = r"(https://github\.com/.+?/.+?)/pull/\d+/commits/([a-f0-9]+)"
    match = re.match(pattern, pr_commit_url)
    if match:
        repo_url = match.group(1)
        commit_hash = match.group(2)
        commit_url = f"{repo_url}/commit/{commit_hash}"
        return commit_url
    else:
        return pr_commit_url

def chmod(target_path):
    run_command(f'chmod -R 777 {target_path}')


def calculate_bleu(reference, candidate):
    ref_tokens = nltk.word_tokenize(reference.lower())
    cand_tokens = nltk.word_tokenize(candidate.lower())
    
    references = [ref_tokens]
    smoothie = SmoothingFunction().method4
    
    score = sentence_bleu(
        references, 
        cand_tokens, 
        weights=(0.25, 0.25, 0.25, 0.25),
        smoothing_function=smoothie
    )
    
    return score
