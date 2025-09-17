from io import StringIO
import os
from common_utils import read_file, run_command, get_nearest_commit_id, get_parent_commit_local, sort_commit_list, parse_localization_info, is_commit1_earlier_than_commit2
from unidiff import PatchSet
from tree_sitter import Language, Parser
import tree_sitter_javascript
import Levenshtein
from difflib import SequenceMatcher
import re
from LLM_handler import deepseek_api, LLM_infer
import ast
import json

logger_file = 'temp.log'
logger_file = 'logging.log'

class FaultLocalizer:
    def __init__(self, project):
        self.project = project
        self.prj_path = project.prj_path
        self.npm_prj_path = project.npm_prj_path
        self.patch_path = project.final_patch_path
        self.vul_commit_version_map = project.vul_commit_version_map
        self.target_file_path = project.target_file_path
        self.unidiff_patch = project.unidiff_patch
        self.patch_id = project.patch_id
        self.pre_patch_id = get_parent_commit_local(self.patch_id, self.npm_prj_path)
        self.localization_info_path = project.localization_info_path
        self.hunks = []
        self.hunk_headers = []
        self.source_functions = []
        # {verison1: [foo1, ...], version2: [foo1,...]}
        self.target_functions = {}
        self.challenge_commit = self.project.get_oldest_vulnerable_version()

        # current_patch = self.project.get_unidiff_patch()
        # self.localization_function()
        # self.localization_context()

        self.source_lines = []
        # len(self.source_lines) == len(self.hunks)
        self.fault_context = []

    def get_long_context_diff(self):
        hunk_lines = get_updown_linenos(self.unidiff_patch)
        for i in range(len(hunk_lines)):
            for line in hunk_lines[i]:
                log_command = f'git log -L {line},{line}:{self.target_file_path} {self.pre_patch_id}'
                history = [i[i.find('diff --git'):] for i in split_commits(run_command(log_command, path=self.npm_prj_path).stdout)]
                for commit in history:
                    if commit.count('\n') > 30:
                        line_content = get_line_content(self.unidiff_patch, line)
                        if line_content is None:
                            continue
                        with open('temp.diff', 'a') as f:
                            print(line, line_content, file=f)
                            print(commit, file=f)

    def localization_line_LLM(self, model):
        localization_file_path = os.path.join(self.localization_info_path, f'{model}.csv')
        # localization_file_path = os.path.join(self.localization_info_path, f'{model}-deletedline.csv')
        # localization_file_path = os.path.join(self.localization_info_path, f'{model}-function.csv')
        # localization_file_path = os.path.join(self.localization_info_path, f'similarity.csv')

        # if os.path.getsize(localization_file_path) != 0: return
        with open(localization_file_path, 'w') as f: ...
        pre_patch_target_file_content = run_command(f'git show {self.pre_patch_id}:{self.project.get_responding_file_name(self.pre_patch_id)}', path=self.npm_prj_path).stdout
        # get target lines of patch version
        hunk_lines_list = get_target_linenos(self.unidiff_patch, pre_patch_target_file_content)
        for index, hunk_lines in enumerate(hunk_lines_list):
            # if index != 0:
            #     continue
            ### pre process
            if hunk_lines[-1] == 'unused':
                continue
            hunk_lines = (list(range(hunk_lines[0], hunk_lines[1]+1)), hunk_lines[-1])

            ### get lines for all archor versions
            changed_commits = self.get_changed_commit_lines_LLM(hunk_lines, model)


            ### get line for the challenge version
            # for q, commit in enumerate(changed_commits):
            #     print(q, commit)
                # run_command(f'git show {commit[0]}:{commit[-1]} > /data/SCA-repair/src/motivation/{self.project.prj_name}-{q}.js', path=self.npm_prj_path)
            changed_commits = [(i[0], i[1][0], i[2]) for i in changed_commits]
            # print(f"changed_commits: {changed_commits}")
            commit = self.project.get_challenge_commit()
            # for commit, version in self.vul_commit_version_map.items():
            nearest_id = get_nearest_commit_id(commit, [i[0] for i in changed_commits], self.npm_prj_path)
            if nearest_id is None:
                if changed_commits[-1][1][0] == -1:
                    changed_lines = [-1]
                else: continue
            else:
                base_commit, base_lineno, base_file_name = changed_commits[nearest_id]
                diff_content = run_command(f'git diff {base_commit}:{self.project.get_responding_file_name(base_commit)} {commit}:{self.project.get_responding_file_name(commit)}', path=self.npm_prj_path).stdout
                changed_lines = parse_lineno_difference(diff_content, base_lineno)
                changed_lines = sorted(list(set(changed_lines)))
                # changed_lines = list(range(changed_lines[0], changed_lines[-1]+1))
            # print(f'{commit}##{changed_lines}##{index}')
            with open(localization_file_path, 'a') as f:
                print(f'{commit}##{changed_lines}##{index}', file=f)

    def get_blame_commit(self, latest_commit, current_file_path, current_hunk_lines):
        if latest_commit.strip() == '':
            return None
        commit_list = []
        for line in current_hunk_lines[0]:
            blame_output = run_git_blame(latest_commit, current_file_path, line, self.npm_prj_path)
            commit_list.extend(parse_git_blame_output(blame_output))
        if not commit_list:
            return None
        current_commit = None
        for commit_hash in commit_list:
            if current_commit is None or not is_commit1_earlier_than_commit2(commit_hash, current_commit, self.npm_prj_path):
                current_commit = commit_hash

        return current_commit

    def get_changed_commit_lines_LLM(self, hunk_lines, model):
        history = []
        before_lines = hunk_lines
        before_commit = self.pre_patch_id
        before_file_path = self.project.get_responding_file_name(before_commit)
        if before_lines[0][0] != -1:
            self.current_line = '\n'.join(self.get_lines_content(before_file_path, before_commit, before_lines[0]))
        while True:
            ### get git blame commit
            if before_lines[0][0] == -1:
                history.append((before_commit, before_lines, before_file_path))
                break
            current_commit = self.get_blame_commit(before_commit, before_file_path, before_lines)
            if current_commit is None or current_commit == before_commit:
                break
            ### line map to Vafter
            current_file_path = self.project.get_responding_file_name(current_commit)
            diff_content = run_command(f'git diff {before_commit}:{before_file_path} {current_commit}:{current_file_path}', path=self.npm_prj_path).stdout
            # print(f'{before_commit} - {current_commit}')
            # print(diff_content)
            after_lines = parse_lineno_difference(diff_content, before_lines[0])
            # print(current_commit, after_lines)
            after_lines = (after_lines, before_lines[-1])
            before_commit = get_parent_commit_local(current_commit, self.npm_prj_path)
            before_file_path = self.project.get_responding_file_name(before_commit)
            # print(f'{current_commit} -> {before_commit}')
            history.append((current_commit, after_lines, current_file_path))
            git_info = run_command(f'git show {current_commit} --name-status', path=self.npm_prj_path).stdout
            if f'A\t{current_file_path}' in git_info:
                break
            if not is_commit1_earlier_than_commit2(self.challenge_commit, current_commit, self.npm_prj_path):
                break
            ### line map between Vbefore and Vafter
            before_lines = self.get_line_map(current_commit, after_lines, before_commit, model)
            # print(before_commit, current_commit, before_lines)
            if before_lines is None or len(before_lines[0]) == 0:
                break
        return history
    
    def line_offset(self, before_commit, current_commit, before_lines, file_path):
        commit_list = run_command(f'git rev-list --first-parent {current_commit}..{before_commit} -- {file_path}', path=self.npm_prj_path).stdout.splitlines()
        b_commit = before_commit
        for i in range(len(commit_list)):
            c_commit = commit_list[i]
            # b_commit_path = self.project.get_responding_file_name(b_commit)
            # c_commit_path = self.project.get_responding_file_name(c_commit)
            diff_content = run_command(f'git diff {b_commit}:{file_path} {c_commit}:{file_path}', path=self.npm_prj_path).stdout
            before_lines = parse_lineno_difference(diff_content, before_lines)
            # print(before_lines, c_commit)
            b_commit = c_commit
        return before_lines

    def get_line_map(self, current_commit, current_hunk_lines, before_commit, model):
        temp_type = current_hunk_lines[-1]
        current_file_path = self.project.get_responding_file_name(current_commit)
        before_file_path = self.project.get_responding_file_name(before_commit)
        if before_file_path is None:
            return None
        # commit_content = run_command(f'git show {current_commit} -- {current_file_path}', path=self.npm_prj_path).stdout
        commit_content = run_command(f'git diff {before_commit}:{before_file_path} {current_commit}:{current_file_path}', path=self.npm_prj_path).stdout
        rev_commit_content = run_command(f'git diff {current_commit}:{current_file_path} {before_commit}:{before_file_path}', path=self.npm_prj_path).stdout
        current_file_content = run_command(f'git show {current_commit}:{current_file_path}', path=self.npm_prj_path).stdout
        before_file_content = run_command(f'git show {before_commit}:{before_file_path}', path=self.npm_prj_path).stdout
        function_range = get_function_range(current_file_content, before_file_content, current_hunk_lines[0])
        # avoid from LLM including other code
        
        target_lines = line_filter(current_hunk_lines[0], commit_content) 
        current_line_content = self.get_lines_content(current_file_path, current_commit, target_lines)
        ### too long context
        # if commit_content.count('\n') > 1000:
        #     return exactly_map(before_file_content, current_line_content)
        # print(commit_content)
        removed_lines = get_removed_lines(commit_content, function_range)
        if len(removed_lines) == 0:
            function_range = [-1,-1]
            removed_lines = get_removed_lines(commit_content, function_range)
        removed_lines = '\n'.join(removed_lines)
        # print(f'function_range: {function_range}')
        # print(f'removed_lines: {removed_lines}')
        before_lines = []
        if removed_lines != '':
            before_lines = LLM_map(removed_lines, current_line_content, model)
            #TODO:
            # print(type(removed_lines))
            # print(type(current_line_content))
            # before_lines = map_lines_for_llm(removed_lines.split('\n'), current_line_content)
            # print(before_lines)
            f = True
            count = 0
            #TODO:
            for i in before_lines:
                if i in removed_lines:
                    f = False
            while f and count < 5:
                count += 1
                before_lines = LLM_map(removed_lines, current_line_content, model, feedback=before_lines)
                for i in before_lines: 
                    if i in removed_lines:
                        f = False
        # print(f'removed_lines: {removed_lines}')
        # print(f'before_lines: {before_lines}')
        if len(before_lines) == 0:
            ## 至少是两个文件的修改
            ## 识别重定向
            before_lines = self.find_rename_line(current_commit, current_line_content)
            if len(before_lines) != 0:
                current_file_path = self.project.get_responding_file_name(current_commit)
                before_file_path = self.project.get_responding_file_name(before_commit)
                commit_content = run_command(f'git show {current_commit} -- {current_file_path}', path=self.npm_prj_path).stdout
                rev_commit_content = run_command(f'git diff {current_commit}:{current_file_path} {before_commit}:{before_file_path}', path=self.npm_prj_path).stdout
                current_file_content = run_command(f'git show {current_commit}:{current_file_path}', path=self.npm_prj_path).stdout
                before_file_content = run_command(f'git show {before_commit}:{before_file_path}', path=self.npm_prj_path).stdout
        if len(before_lines) == 0:
            if current_hunk_lines[-1] == 'add':
                before_line = get_add_place(commit_content, current_line_content, target_lines)
                if before_line is None:
                    return 
                before_file_lines = before_file_content.split('\n')
                before_file_length = len(before_file_lines)
                if before_line > before_file_length or (before_line == before_file_length and before_file_lines[-1].strip() == ''):
                    before_line = -1
                before_lines = [before_line]
            else:
                before_lines = self.get_add_lines(commit_content, target_lines)
                temp_type = 'add'
                if before_lines is None:
                    return None
        else:
            # print(before_lines)
            #TODO:
            # if len(before_lines) != len(target_lines):
            # if len(before_lines) > 1:
            #     before_lines = self.filter_1nmap_lines(before_lines, model)
            print(before_lines)
            before_lines = exactly_map(before_file_content, before_lines, function_range)
            print(before_lines)
            before_lines.sort()
        rest_lines = [i for i in current_hunk_lines[0] if i not in target_lines]
        rest_lines = parse_lineno_difference(rev_commit_content, rest_lines)
        before_lines.extend(rest_lines)
        return (before_lines, temp_type)

    def get_add_lines(self, content, target_lines):
        patch = PatchSet(StringIO(content))
        max_line = max(target_lines)
        for patched_file in patch:
            for hunk in patched_file:
                for line in hunk:
                    if line.target_line_no is not None and line.target_line_no > max_line and line.source_line_no is not None:
                        return [line.source_line_no]

    def filter_1nmap_lines(self, lines, model):
        result_lines = []
        for line in lines:
            if is_related_LLM(self.current_line, line, model):
                result_lines.append(line)
        return result_lines

    def find_rename_line(self, commit, line_content):
        # TODO: line 寻找结果需要保持唯一
        commit_content = filter_js_hunks(run_command(f'git show {commit}', path=self.npm_prj_path).stdout)
        with open('./temp/temp.diff', 'w') as f:
            f.write(commit_content)
        patch_set = PatchSet(StringIO(commit_content))
        result_lines = []
        js_file_count = 0
        for patched_file in patch_set:
            if patched_file.source_file.endswith('.js'):
                js_file_count += 1
        if js_file_count < 2:
            return []
        for patched_file in patch_set:
            removed_lines = []
            for hunk in patched_file:
                for line in hunk:
                    if line.is_removed:
                        removed_lines.append((line.value.strip(), line.source_line_no))
            for target_line in line_content:
                for removed_line, line_number in removed_lines:
                    similarity = SequenceMatcher(None, target_line, removed_line).ratio()
                    if similarity >= 0.9:
                        result_lines.append(removed_line)
                        target_file = patched_file.source_file
        if len(result_lines):
            self.project.name_history.append((commit, self.project.get_responding_file_name(commit)))
            rename_history = self.project.get_target_name_history(os.path.join(self.project.npm_prj_path, target_file[2:]))
            self.project.name_history.extend(rename_history)
            self.project.name_history = self.sort_name_history(self.project.name_history)
            self.project.write_name_history()
        return result_lines

    def sort_name_history(self, name_history):
        name_history = list(set(name_history))
        from functools import cmp_to_key
        def custom_compare(a, b):
            if is_commit1_earlier_than_commit2(a[0], b[0], path=self.npm_prj_path):
                return 1
            else: return -1
        return sorted(name_history, key=cmp_to_key(custom_compare))

    def change_target_name_history(self, target_file):
        rename_history = self.project.get_target_name_history(os.path.join(self.project.npm_prj_path, target_file[2:]))
        self.project.name_history.extend(rename_history)

    def get_lines_content(self, file_path, commit, line_numbers):
        file_lines = run_command(f'git show {commit}:{file_path}', path=self.npm_prj_path).stdout.splitlines()
        line_content = []
        for line_number in line_numbers:
            if line_number > len(file_lines) or line_number < 1:
                raise ValueError(f"Line number {line_number} is out of range")
            line_content.append(file_lines[line_number-1])
        return line_content

#     def LLM_map(self, removed_lines, current_hunk_lines, model):
#         target_content = '\n'.join(current_hunk_lines)
#         prompt = f'''As a JavaScript code semantics expert, you are required to identify the code snippet from the target codebase that is most semantically similar to the given code.

# Input: Target codebase and given code

# Output:
# The code from the target codebase that is most semantically similar to the given code

# Output Format Requirements:
# 1. Output a Python-style list where each element contains only one line of content, e.g., [\'\'\'line A content\'\'\', \'\'\'line B content\'\'\'].
# 2. Do not use ``` or any explanatory text.
# 3. If no match is found, output [].

# Now, process the following input:

# Target codebase:

# {removed_lines}

# Given code:

# {target_content}

# The most semantically similar lines:
# '''
#         LLM_output = LLM_infer(prompt, model)
#         # LLM_output = ast.literal_eval(LLM_output.strip('`'))
#         print('----------------prompt----------------')
#         print(prompt)
#         print('----------------output----------------')
#         print(LLM_output)
#         print('--------------------------------')
#         LLM_output = ast.literal_eval(LLM_output[LLM_output.find('['):LLM_output.rfind(']')+1])
#         return LLM_output
        
    ### git log -L
    def localization_line_log(self):
        localization_file_path = os.path.join(self.localization_info_path, f'git_log.csv')
        with open(localization_file_path, 'w') as f: ...
        hunk_lines = get_updown_linenos_for_chunk(self.unidiff_patch)
        # hunk_lines = get_updown_linenos(self.unidiff_patch)
        print(hunk_lines)
        # print(hunk_lines)
        for i in range(len(hunk_lines)):
            changed_commits = self.get_changed_commit_lines(hunk_lines[i])
            for commit, version in self.vul_commit_version_map.items():
                nearest_id = get_nearest_commit_id(commit, [i[0] for i in changed_commits], self.npm_prj_path)
                if nearest_id is None:
                    continue
                # TODO: simply added line
                base_commit, base_lineno, base_file_name = changed_commits[nearest_id]
                diff_content = run_command(f'git diff {base_commit}:{self.project.get_responding_file_name(base_commit)} {commit}:{self.project.get_responding_file_name(commit)}', path=self.npm_prj_path).stdout
                changed_lines = parse_lineno_difference(diff_content, base_lineno)
                changed_lines = sorted(list(set(changed_lines)))
                changed_lines = list(range(changed_lines[0], changed_lines[-1]+1))
                with open(localization_file_path, 'a') as f:
                    print(f'{commit}##{changed_lines}##{i}', file=f)

    def get_changed_commit_lines(self, lines):
        changed_commit_ids = []
        for line in lines:
            changed_commit_ids.extend(self.get_changed_commits(line))
        changed_commit_ids = sort_commit_list(self.patch_id, list(set(changed_commit_ids)), self.npm_prj_path)
        before_lines = lines
        before_commit = get_parent_commit_local(self.patch_id, self.npm_prj_path)
        changed_commits = []
        for changed_commit_id in changed_commit_ids:
            diff_content = run_command(f'git diff {before_commit}:{self.project.get_responding_file_name(before_commit)} {changed_commit_id}:{self.project.get_responding_file_name(changed_commit_id)}', path=self.npm_prj_path).stdout

            after_lines = parse_lineno_difference(diff_content, before_lines)

            before_commit = get_parent_commit_local(changed_commit_id, self.npm_prj_path)
            before_lines = self.get_mapped_lines(changed_commit_id, after_lines, before_commit)

            changed_commits.append((changed_commit_id, after_lines, self.project.get_responding_file_name(changed_commit_id)))
        return changed_commits

    def get_changed_file_name(self, commit_id, lines, file_name):
        changed_file_name = None
        for line in lines:
            history = run_command(f'git log -L {line},{line}:{file_name} -n 1 {commit_id}', path=self.npm_prj_path).stdout
            pattern = r"^---\s+(.+)\n\+\+\+\s+(.+)$"
            rename_match = re.search(pattern, history, re.MULTILINE)
            if rename_match:
                old_file = rename_match.group(1).strip()
                new_file = rename_match.group(2).strip()
                if old_file != '/dev/null':
                    changed_file_name = old_file
                else:
                    changed_file_name = new_file
        return changed_file_name[2:]

    def get_mapped_lines(self, commit_id, after_lines, before_commit):
        unchanged_lines = []
        changed_lines = []
        commit_content = run_command(f'git diff {commit_id}:{self.project.get_responding_file_name(commit_id)} {before_commit}:{self.project.get_responding_file_name(before_commit)}', path=self.npm_prj_path).stdout
        for line in after_lines:
            history = run_command(f'git log -L {line},{line}:{self.project.get_responding_file_name(commit_id)} -n 1 {commit_id}', path=self.npm_prj_path).stdout
            if commit_id not in history:
                unchanged_lines.append(line)
                continue
            changed_lines.extend(get_changed_linenos(PatchSet(StringIO(history))))
        unchanged_lines = parse_lineno_difference(commit_content, unchanged_lines)
        return list(set(unchanged_lines + changed_lines))

    def get_changed_commits(self, line):
        # if isinstance(line, tuple):
        #     line_para = f'{line[0]},{line[1]}'
        # else:
        #     line_para = f'{line},{line}'
        log_command = f'git log -L {line},{line}:{self.target_file_path} {self.pre_patch_id}'
        history = split_commits(run_command(log_command, path=self.npm_prj_path).stdout)
        changed_commit_ids = [get_commit_id(change) for change in history]
        return changed_commit_ids

    def localization_context(self):
        target_file_path = os.path.join(self.prj_path, 'target.js')
        # self.source_lines, self.hunk_headers, self.hunks = get_source_lines(self.unidiff_patch)
        # context_lines = get_target_context(self.hunk_headers, self.source_lines, target_file_path)
        source_lines = self.get_continuous_hunk_content()
        context_lines = get_target_context(source_lines, target_file_path)
        self.write_localization_result(context_lines)
        return context_lines
            
    def write_localization_result(self, context_lines):
        target_file = os.path.join(self.localization_info_path, 'LLM-git.csv')
        challenge_version = self.project.get_challenge_commit()
        with open(target_file, 'w') as f:
            for index, line in enumerate(context_lines):
                result = f'{challenge_version}##{line}##{index}'
                print(result, file=f)


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
                            modifications.append(current_chunk)
                        current_chunk = []
                if current_chunk:
                    modifications.append(current_chunk)
                    current_chunk = []
        deleted_modifications = []
        for chunk in modifications:
            temp_chunk = []
            for line in chunk:
                if line.startswith('-'):
                    temp_chunk.append(line[1:])
            deleted_modifications.append(temp_chunk)
        return deleted_modifications

    #TODO:
    def localization_function(self):
        # [hunk, hunk, hunk...]
        pre_patch_localizations, post_patch_localizations = get_source_patch_localization(self.patch_path)
        pre_content = run_command(f'git show {self.project.patch_id}^:{self.unidiff_patch[0].path}', path=self.project.npm_prj_path).stdout
        post_content = run_command(f'git show {self.project.patch_id}:{self.unidiff_patch[0].path}', path=self.project.npm_prj_path).stdout
        pre_patch_localizations, pre_all_functions = self.load_source_function(pre_patch_localizations, pre_content)
        post_patch_localizations, post_all_functions = self.load_source_function(post_patch_localizations, post_content)
        def get_function(localization):
            return [j for i in localization if 'source_function' in i for j in i.get('source_function') ]
        pre_functions = get_function(pre_patch_localizations)
        post_functions = get_function(post_patch_localizations)
        return pre_functions, post_functions, pre_all_functions, post_all_functions
        # for commit_id, version in self.vul_commit_version_map.items():
        #     self.project.checkout(commit_id)
        #     if not os.path.exists(self.target_file_path):
        #         continue
        #     self.load_function_map(patch_localizations, version)
        # # return patch_localizations

    def load_source_function(self, patch_localizations, target_file_content):
        # source_functions = []
        target_function_dict = ast_parse(target_file_content)
        for patch_localization in patch_localizations:
            target_functions = get_target_function(target_function_dict, patch_localization)
            if len(target_functions) != 0:
                patch_localization.setdefault('source_function', target_functions)  
        return patch_localizations, [i for i in target_function_dict.values()]

    def load_function_map(self, patch_localizations, version):
        self.target_functions.setdefault(version, [])
        target_functions, global_function = ast_parse(self.target_file_path)
        for patch_localization in patch_localizations:
            # final_functions = []
            for source_function in patch_localization['source_function']:
                self.hunks.append(patch_localization['hunk'])
                self.source_functions.append(source_function)
                distance = float('inf')
                final_function = None
                if source_function[0] == 'global':
                    final_function = global_function
                else:
                    for t in target_functions.values():
                        if t[0] == source_function[0] and 'anonymous' not in t[0].lower() and 'module.exports' not in t[0].lower():
                            final_function = t
                            break
                        current_distance = Levenshtein.distance(source_function[1], t[1])/(len(source_function[1])+len(t[1]))
                        if distance > current_distance:
                            distance = current_distance
                            final_function = t
                self.target_functions.get(version).append(final_function)

                # if final_function is not None and final_function not in final_functions:
                #     final_functions.append(final_function)
            # patch_localization.setdefault(f"{version}-backport_function", final_functions)

    def analyze_function_localization(self):
        baseline_json_path = 'data-study/baseline-data/baseline.json'
        pre_functions, post_functions, pre_all_functions, post_all_functions = self.localization_function()
        changed_functions = get_changed_functions(pre_functions, post_functions, pre_all_functions, post_all_functions)
        # if len(changed_functions) != 1:
        #     return
        target_commit = self.project.get_challenge_commit()
        target_file_content = run_command(f'git show {target_commit}:{self.unidiff_patch[0].path}', path=self.project.npm_prj_path).stdout
        target_functions = ast_parse(target_file_content).values()
        result_dict = {}
        for index, changed_function in enumerate(changed_functions):
            target_function_body = query_function_body(changed_function, target_functions)
            # if target_function_body is None:
            #     return
            pre_function_body = query_function_body(changed_function, pre_all_functions)
            post_function_body = query_function_body(changed_function, post_all_functions)
            key = f'{self.prj_path.split('/')[-1]}#mysitque-{index}.js#{changed_function}'
            result_dict[key] = {'method_name': changed_function, 'target_before': target_function_body, 'origin_before': pre_function_body, 'origin_after': post_function_body, 'target_after': 'function test() {let a=1;\nletb=a;\n}'}
        update_json(result_dict, baseline_json_path)


def update_json(added_data, json_path):
    try:
        with open(json_path) as f:
            data = json.load(f)
    except json.decoder.JSONDecodeError:
        data = {}
    data.update(added_data)
    with open(json_path, 'w') as f:
        json.dump(data, f, indent=4)

def query_function_body(function_name, query_functions):
    for query_function in query_functions:
        if function_name == query_function[0]:
            return query_function[1]
    return None

def get_changed_functions(pre_functions, post_functions, pre_all_functions, post_all_functions):
    changed_functions = list(set([i[0] for i in pre_functions+post_functions if i[0] in [j[0] for j in pre_all_functions] and i[0] in [j[0] for j in post_all_functions]]))
    return changed_functions

def get_source_patch_localization(patch_path):
    # added_line, path, hunk
    post_patch_localizations = []
    pre_patch_localizations = []
    patch_content = read_file(patch_path)
    patch_set = PatchSet(StringIO(patch_content))
    for patched_file in patch_set:
        for hunk in patched_file:
            added_line = []
            deleted_line = []
            for line in hunk:
                if line.is_added:
                    added_line.append(line.target_line_no)
                if line.is_removed:
                    deleted_line.append(line.source_line_no)
            # if len(added_line) == 0:
            #     for line in hunk:
            #         if line.is_removed:
            #             added_line.append(line.source_line_no+hunk.target_start-hunk.source_start)
            # patch_localizations.append({'added_line': added_line, 'path': patched_file.path, 'hunk': hunk})
            post_patch_localizations.append({'line': added_line, 'path': patched_file.path})
            pre_patch_localizations.append({'line': deleted_line, 'path': patched_file.path})
    return pre_patch_localizations, post_patch_localizations
    
def get_target_function(target_function_dict, patch_localization):
    # print([i[0] for i in target_function_dict.values()])
    target_functions = []
    for line in patch_localization['line']:
        target_function = None
        target_function_index = None
        for i in target_function_dict:
            # TODO:
            if i[0] < line and i[1] >= line:
                if 'Anonymous Function' in target_function_dict[i][0] or 'Anonymous Arrow Function' in target_function_dict[i][0]:
                    continue
                query_function = ((i[0], i[1]), target_function_dict[i])
                if target_function is None:
                    target_function = query_function
                    target_function_index = i
                elif i[0] >= target_function_index[0] and i[1] <= target_function_index[1]:
                    target_function = query_function
                    target_function_index = i

        if target_function not in target_functions and target_function is not None:
            for t in target_functions:
                if t[0] in target_function:
                    target_functions.remove(t)
            target_functions.append(target_function)
    result_functions = []
    for function in target_functions:
        in_flag = False
        for query_function in  target_functions:
            if function == query_function:
                continue
            elif function[0][0] >= query_function[0][0] and function[0][1] <= query_function[0][1]:
                in_flag = True
        if not in_flag:
            result_functions.append(function[1])
    return [i[1] for i in target_functions]
    # return result_functions, target_function_dict
        # if target_function is None and global_function not in target_functions:
        #     target_functions.append(global_function)
            # print(target_file_path)
            # if target_function_index[0] in patch_localization['added_line'] and target_function_index[1] in patch_localization['added_line']:
            #     print(backporter.patch_path, backporter.target_file_path)
    
def get_line_context(file_content, lines):
    line_structure_dict = {}
    file_content_lines = file_content.splitlines()
    return '\n'.join(file_content_lines[lines[0]-1: lines[-1]])
    for line in lines:
        line_content = file_content_lines[line-1].strip()
        if line_content == '':
            continue
        line_structure_dict[line] = line_content
    return line_structure_dict

def get_context(file_content, lines):
    # print(file_content)
    file_content_lines = file_content.splitlines()
    file_content = file_content.encode('utf-8')
    JS_LANGUAGE = Language(tree_sitter_javascript.language())
    parser = Parser(JS_LANGUAGE)
    tree = parser.parse(file_content)
    target_types = ['statement', 'declaration', 'comment']
    line_structure_dict = {}
    def find_minimal_structure(root_node, target_line, line_content):
        target_line_0based = target_line - 1
        best_node = None
        max_depth = -1
        stack = [(root_node, 0)]  # (node, depth)
        while stack:
            node, depth = stack.pop()
            start_line, _ = node.start_point
            end_line, _ = node.end_point
            if start_line <= target_line_0based <= end_line:
                node_content = file_content[node.start_byte:node.end_byte].decode('utf8')  
                if depth > max_depth and any(i for i in target_types if i in node.type) and line_content in node_content:
                    best_node = node
                    max_depth = depth
                elif depth == max_depth:
                    current_span = node.end_byte - node.start_byte
                    best_span = best_node.end_byte - best_node.start_byte
                    if current_span < best_span and any(i for i in target_types if i in node.type) and line_content in node_content:
                        best_node = node
                for child in reversed(node.children):
                    stack.append((child, depth + 1))
        return best_node
    for line in lines:
        line_content = file_content_lines[line-1].strip()
        if line_content == '':
            continue
        target_node = find_minimal_structure(tree.root_node, line, line_content)
        if file_content[target_node.start_byte-target_node.start_point[1]:target_node.start_byte].decode('utf8').strip() != '':
            target_content = file_content[target_node.start_byte:target_node.end_byte].decode('utf8')        
        else:
            target_content = file_content[target_node.start_byte-target_node.start_point[1]:target_node.end_byte].decode('utf8')
        line_structure_dict[line] = target_content
    return line_structure_dict

def ast_parse(source_content):
    # source_content = read_file(source_path).encode('utf-8')
    source_content = source_content.encode('utf-8')
    JS_LANGUAGE = Language(tree_sitter_javascript.language())
    parser = Parser(JS_LANGUAGE)
    tree = parser.parse(source_content)
    function_ranges = {}
    def extract_function_names(node, code, function_ranges):
        if node.type == 'function_declaration':
            function_name_node = node.child_by_field_name('name')
            if function_name_node:
                function_name = code[function_name_node.start_byte:function_name_node.end_byte].decode('utf8')
                function_body = code[node.start_byte:node.end_byte].decode('utf8')
                start_line, end_line = node.start_point[0]+1, node.end_point[0]+1
                function_ranges[(start_line, end_line)] = (function_name, function_body)
        elif node.type == 'function_expression':
            parent = node.parent
            # if '"pdfinfo' in code[node.start_byte:node.end_byte].decode('utf8'):
            #     print(node.parent.type)
            #     key_node = node.parent.child_by_field_name('key')
            #     print(code[key_node.start_byte:key_node.end_byte].decode('utf8'))
            if parent.type == 'assignment_expression':
                left_node = parent.child_by_field_name('left')
                if left_node.type == 'identifier':
                    function_name = f"{left_node.text.decode('utf8')}"
                elif left_node.type == 'member_expression':
                    obj_name = left_node.child_by_field_name('object').text.decode('utf8')
                    prop_name = left_node.child_by_field_name('property').text.decode('utf8')
                    function_name = f"{obj_name}.{prop_name}"
                else:
                    function_name = 'Anonymous Function'
            elif parent.type == 'variable_declarator':
                function_name_node = node.parent.child_by_field_name('name') if node.parent else None
                if function_name_node:
                    function_name = code[function_name_node.start_byte:function_name_node.end_byte].decode('utf8')
            elif node.parent.type == 'pair':
                key_node = node.parent.child_by_field_name('key')
                function_name = code[key_node.start_byte:key_node.end_byte].decode('utf8')
            else:
                function_name = 'Anonymous Function'
            if function_name != 'Anonymous Function':
                source_node = node.parent
            else: source_node = node
            # source_node = node
            function_body = code[source_node.start_byte:source_node.end_byte].decode('utf8')
            start_line, end_line = source_node.start_point[0]+1, source_node.end_point[0]+1
            function_ranges[(start_line, end_line)] = (function_name, function_body)
        elif node.type == 'arrow_function':
            # print(node)
            function_name = 'Anonymous Arrow Function'
            if node.parent:
                function_name_node = node.parent.child_by_field_name('name')
                if not function_name_node:
                    function_name_node = node.parent.child_by_field_name('key')
                if function_name_node:
                    function_name = code[function_name_node.start_byte:function_name_node.end_byte].decode('utf8')
            if function_name!= 'Anonymous Arrow Function':
                source_node = node.parent
            else: source_node = node
            source_node = node
            function_body = code[source_node.start_byte:source_node.end_byte].decode('utf8')
            start_line, end_line = source_node.start_point[0]+1, source_node.end_point[0]+1
            function_ranges[(start_line, end_line)] = (function_name, function_body)
        elif node.type == 'method_definition':
            function_body = code[node.start_byte:node.end_byte].decode('utf8')
            method_name_node = node.child_by_field_name('name')
            if method_name_node:
                method_name = code[method_name_node.start_byte:method_name_node.end_byte].decode('utf8')
                start_line, end_line = node.start_point[0]+1, node.end_point[0]+1
                function_ranges[(start_line, end_line)] = (method_name, function_body)
        for child in node.children:
            extract_function_names(child, source_content, function_ranges)
        return function_ranges
    functions = extract_function_names(tree.root_node, source_content, function_ranges)
    # global_function = ('global', get_global_function(source_content, functions.keys()))
    # for k, v in functions.items():
    #     print(k, v)
    # return functions, global_function
    return functions

def get_global_function(source_code, function_range_list):
    code_lines = source_code.splitlines()
    # print(code_lines)
    lines_in_function = set()
    for start, end in function_range_list:
        lines_in_function.update(range(start, end + 1))
    global_code_lines = [
        line for index, line in enumerate(code_lines, start=1) if index not in lines_in_function
    ]
    return '\n'.join(global_code_lines)

def get_target_context(source_lines, target_file_path):
    # print(source_lines)
    # context_lines = map_lines(source_lines, target_file_path)
    context_lines = map_lines_LLM(source_lines, target_file_path)
    context_lines = fine_tune_lines(context_lines, target_file_path)
    # with open(logger_file, 'a') as f:
    #     print(context_lines, file=f)
    # print(context_lines)
    return context_lines

def fine_tune_lines(context_lines, target_file_path):
    for context_line in context_lines:
        for i in range(len(context_line)-2, -1, -1):
            if context_line[i] == -1:
                context_line[i] = find_no_blank_line(context_line[i+1], target_file_path, -1)
    for context_line in context_lines:
        for i in range(1, len(context_line)):
            if context_line[i] == -1:
                context_line[i] = find_no_blank_line(context_line[i-1], target_file_path, 1)
    context_lines = [i for i in context_lines if i != -1]
    return context_lines

def find_no_blank_line(line, target_file_path, direction):
    if line == -1:
        return -1
    with open(target_file_path, 'r', encoding='utf-8') as file:
        lines = file.readlines()
        if direction == -1:
            for i in range(line-2, -1, -1):
                if lines[i].strip():
                    return i+1
        else:
            for i in range(line, len(lines)):
                if lines[i].strip():
                    return i+1
    return -1




def map_lines(source_lines, target_file_path):
    context_lines = []
    for i in range(len(source_lines)):
        parent_line = 1
        # if len(hunk_headers[i].strip()) != 0:
        #     parent_line = find_line_number(target_file_path, hunk_headers[i])
        current_lines = []
        for line in source_lines[i]:
            if len(line.strip()) < 3:
                continue
            tmp = find_line_similarity(target_file_path, line, start_line=parent_line)
            # tmp = find_line_number(target_file_path, line, start_line=parent_line)
            current_lines.append(tmp)
            if tmp != -1:
                parent_line = tmp
        context_lines.append(current_lines)
    return context_lines

def map_lines_LLM(source_lines, target_file_path):
    with open(target_file_path) as f:
        target_content = f.read()
    context_lines = []
    print(source_lines)
    for i in range(len(source_lines)):
        current_lines = []
        for line in source_lines[i]:
            map_lines = LLM_map(line, target_content.split('\n'), 'deepseek-api')
            line_numbers = exactly_map(target_content, map_lines, [-1, -1])
            current_lines.extend(line_numbers)
        context_lines.append(current_lines)
    return context_lines

# incoparate git history for LLM
def map_lines_for_llm(removed_lines, current_hunk_lines):
    current_lines = []
    for target_line in current_hunk_lines:
        if len(target_line.strip()) < 3:
            continue
        max_similarity = 0
        most_similar_line = ''
        for line in removed_lines:
            similarity = SequenceMatcher(None, string_normalize(target_line), string_normalize(line)).ratio()
            if similarity > max_similarity:
                max_similarity = similarity
                most_similar_line = line
        current_lines.append(most_similar_line)
    return current_lines

def LLM_map(removed_lines, current_hunk_lines, model, feedback=False, feedback_error=False):
    target_content = '\n'.join(current_hunk_lines)
    prompt = f'''As a JavaScript code semantics expert, you are required to identify the code snippet from the target codebase that is most semantically similar to the given code. Please try to find corresponding code for each line as much as possible.

Input: Target codebase and given code.

Output:
The code from the target codebase that is most semantically similar to the given code.

Output Format Requirements:
1. Output a Python-style list where each element contains only one line of content, e.g., [\'\'\'line A content\'\'\', \'\'\'line B content\'\'\' ... \'\'\'line N content\'\'\'].
2. The output code must be from the target codebase, not the given code.
3. Do not use ``` or any explanatory text.
4. If no match is found, output [].

Now, process the following input:

Target codebase:

{removed_lines}

Given code:

{target_content}

The most semantically similar lines:
'''
    if feedback is not False:
        prompt += f'''
Please note that in your last response, you output code ({feedback}) that was not in the target codebase. Do not make this mistake again. Please output code that is exactly the same as in the target codebase.
'''
    if feedback_error is not False:
        prompt += 'Please note that your returned result does not conform to our output format (Output a Python-style list where each element contains only one line of content, e.g., [\'\'\'line A content\'\'\', \'\'\'line B content\'\'\' ... \'\'\'line N content\'\'\']). Please re-output it.'
    LLM_output = LLM_infer(prompt, model)
    # LLM_output = ast.literal_eval(LLM_output.strip('`'))

    # print('----------------prompt----------------')
    # print(prompt)
    # print('----------------output----------------')
    # print(LLM_output)
    # print('--------------------------------')
    try:
        LLM_output = ast.literal_eval(LLM_output[LLM_output.find('['):LLM_output.rfind(']')+1])
    except:
        LLM_map(removed_lines, current_hunk_lines, model, feedback=False, feedback_error=True)
    return LLM_output



def find_line_number(file_path, target_line, start_line=1):
    with open(file_path, 'r', encoding='utf-8') as file:
        for current_line_number, line in enumerate(file, start=1):
            if current_line_number < start_line:
                continue
            if string_normalize(line) == string_normalize(target_line):
                return current_line_number
    return -1

def find_line_similarity(file_path, target_line, start_line=1):
    with open(file_path, 'r', encoding='utf-8') as file:
        lines = file.readlines()
    if not lines:
        return -1
    max_similarity = 0
    most_similar_line_number = -1
    for line_number, line in enumerate(lines, start=1):
        if line_number < start_line:
            continue
        similarity = SequenceMatcher(None, string_normalize(target_line), string_normalize(line)).ratio()
        if similarity > max_similarity:
            max_similarity = similarity
            most_similar_line_number = line_number
    return most_similar_line_number

def get_source_lines(unidiff_patch):
    source_lines = []
    hunk_headers = []
    hunks = []
    for patch in unidiff_patch:
        for hunk in patch:
            current_source_lines = []
            hunk_headers.append(hunk.section_header)
            hunks.append(hunk)
            for line in hunk:
                # if line.line_type == ' '  line.line_type == '-':
                if line.line_type == '-':
                    current_source_lines.append(line.value)
            source_lines.append(current_source_lines)
    return source_lines, hunk_headers, hunks

def string_normalize(str):
    return str.strip().replace(" ", "")

def get_line_count(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        return file.readlines()

def is_tangled_line(line):
    if len(line.strip()) <= 3 or line.strip().startswith('//'):
        return True
    return False

def get_target_linenos(patch, pre_patch_target_file_content):
    modifications = []
    for patched_file in patch:
        file_name = patched_file.path
        for hunk in patched_file:
            current_delete = []
            current_add = []
            for line in hunk:
                if 'No newline at end of file' in line.value:
                    continue
                if line.is_removed:
                    # if not is_tangled_line(line.value):
                    current_delete.append(line.value.strip('\n'))
                elif line.is_added:
                    # if not is_tangled_line(line.value):
                    current_add.append(line.value.strip('\n'))
                else:
                    if current_delete and current_add:
                        old_start = line.source_line_no - len(current_delete)
                        old_end = old_start + len(current_delete) - 1
                        modifications.append({
                            "type": "change",
                            "old_start": old_start,
                            "old_end": old_end,
                            "old_lines": current_delete,
                            "new_lines": current_add,
                            "file": file_name
                        })
                    elif current_delete:
                        old_start = line.source_line_no - len(current_delete)
                        old_end = old_start + len(current_delete) - 1
                        modifications.append({
                            "type": "delete",
                            "old_start": old_start,
                            "old_end": old_end,
                            "old_lines": current_delete,
                            "new_lines": [],
                            "file": file_name
                        })
                    elif current_add:
                        old_start = line.source_line_no
                        old_end = line.source_line_no
                        modifications.append({
                            "type": "add",
                            "old_start": old_start,
                            "old_end": old_end,
                            "old_lines": [],
                            "new_lines": current_add,
                            "file": file_name
                        })
                    current_delete = []
                    current_add = []

            if current_delete and current_add:
                old_start = hunk.source_start + hunk.source_length - len(current_delete)
                old_end = old_start + len(current_delete) - 1
                modifications.append({
                    "type": "change",
                    "old_start": old_start,
                    "old_end": old_end,
                    "old_lines": current_delete,
                    "new_lines": current_add,
                    "file": file_name
                })
            elif current_delete:
                old_start = hunk.source_start + hunk.source_length - len(current_delete)
                old_end = old_start + len(current_delete) - 1
                modifications.append({
                    "type": "delete",
                    "old_start": old_start,
                    "old_end": old_end,
                    "old_lines": current_delete,
                    "new_lines": [],
                    "file": file_name
                })
            elif current_add:
                old_start = hunk.source_start + hunk.source_length
                old_end = hunk.source_start + hunk.source_length
                modifications.append({
                    "type": "add",
                    "old_start": old_start,
                    "old_end": old_end,
                    "old_lines": [],
                    "new_lines": current_add,
                    "file": file_name
                })
    pre_file_lines = pre_patch_target_file_content.split('\n')
    pre_file_length = len(pre_file_lines)
    # for i in modifications:
    #     all_lines = i["old_lines"] + i["new_lines"]
    #     if all(is_tangled_line(i) for i in all_lines):
    #         i['type'] = 'unused'
    for i in modifications:
        if i['type'] == 'unused':
            continue
        if i['type'] == 'add':
            if i["old_end"] < pre_file_length:
                while pre_file_lines[i['old_end']-1].strip() == '':
                    i['old_end'] += 1
                    i["old_start"] += 1
                    if i["old_end"] >= pre_file_length:
                        break
            if i["old_end"] > pre_file_length or (i["old_end"] == pre_file_length and pre_file_lines[-1].strip() == ''):
                i["old_start"] = -1
                i["old_end"] = -1
    return [(i["old_start"], i["old_end"], i["type"]) for i in modifications]


def get_add_context(unidiff_patch):
    changed_lines = []
    for patch in unidiff_patch:
        for hunk in patch:
            for line in hunk:
                if line.is_removed:
                    changed_lines.append(line.source_line_no)
    return changed_lines

def get_changed_linenos(unidiff_patch):
    changed_lines = []
    for patch in unidiff_patch:
        for hunk in patch:
            for line in hunk:
                if line.is_removed:
                    changed_lines.append(line.source_line_no)
    return changed_lines

def merge_consecutive_numbers(arr):
    arr.sort()
    result = []
    start = arr[0]
    end = arr[0]
    for i in range(1, len(arr)):
        if arr[i] == end + 1:
            end = arr[i]
        else:
            if start == end:
                result.append(start)
            else:
                result.append((start, end))
            start = end = arr[i]
    if start == end:
        result.append(start)
    else:
        result.append((start, end))
    return result

def get_commit_id(log_text):
    return re.search(r"commit ([a-f0-9]{40})", log_text).group(1)

def parse_git_diff(log_text):
    # print(log_text)
    commit_id = re.search(r"commit ([a-f0-9]{40})", log_text).group(1)
    patch = PatchSet(StringIO(log_text))
    target_linenos = []
    for patched_file in patch:    
        target_file_name = patched_file.path
        for hunk in patched_file:
            for line in hunk:
                if line.is_added:
                    target_linenos.append(line.target_line_no)
    return commit_id, target_linenos, target_file_name

def split_commits(input_text):
    commits = re.split(r"(?=^commit [a-f0-9]{40})", input_text, flags=re.MULTILINE)
    # # return commits
    # for i in commits:
    #     print(i)
    #     print('-'*50)
    return [commit for commit in commits if commit.strip()]

def parse_lineno_difference(diff_content, lineno):
    patch = PatchSet(StringIO(diff_content))
    target_lino_list = []
    for current_line in lineno:
        result_line = current_line
        is_in_hunk = False
        for patched_file in patch:
            for hunk in patched_file:
                old_start = hunk.source_start
                old_end = old_start + hunk.source_length - 1
                new_start = hunk.target_start
                new_end = new_start + hunk.target_length - 1
                if current_line < old_start:
                    continue
                if current_line > old_end:
                    line_delta = hunk.target_length - hunk.source_length
                    result_line += line_delta
                    continue
                for line in hunk:
                    if line.source_line_no == current_line and line.target_line_no is None:
                        # print(f'line.value: {line.value}')
                        target_lino = find_added_lines(diff_content, line.value.strip())
                        if target_lino is not None:
                            target_lino_list.append(target_lino)
                        is_in_hunk = True
                    if line.source_line_no == current_line and not line.is_removed:
                        target_lino_list.append(line.target_line_no)
                        is_in_hunk = True
                if is_in_hunk:
                    break
        if not is_in_hunk:
            target_lino_list.append(result_line)
    return target_lino_list

def get_updown_linenos(unidiff_patch):
    hunks = []
    for patch in unidiff_patch:
        for hunk in patch:
            # hunks.append([hunk.source_start, hunk.source_start + hunk.source_length - 1])
            hunks.append(list(range(hunk.source_start, hunk.source_start + hunk.source_length)))
    return hunks

def get_updown_linenos_for_chunk(unidiff_patch):
    modifications = []
    for patched_file in unidiff_patch:
        for hunk in patched_file:
            current_chunk = []
            for line in hunk:
                if 'No newline at end of file' in line.value:
                    continue
                if line.is_removed or line.is_added:
                    current_chunk.append(line)  
                else:
                    if current_chunk:
                        modifications.append([i.source_line_no for i in current_chunk if i.is_removed])
                    current_chunk = []
            if current_chunk:
                modifications.append([i.source_line_no for i in current_chunk if i.is_removed])
                current_chunk = []
    return modifications


def get_removed_lines(patch_content, function_range):
    if function_range == [-1, -1]:
        r = range(1, 100000)
    else: r = range(function_range[0], function_range[1]+1)
    # else: r = range(1, 100000) ### ablate fucntion range
    unidiff_patch = PatchSet(StringIO(patch_content))
    removed_lines = []
    for patch in unidiff_patch:
        for hunk in patch:
            for line in hunk:
                if line.is_removed and line.source_line_no in r:
                # if line.source_line_no in r: ### ablate deleted_line
                    removed_lines.append(line.value.strip())
    return removed_lines

# def get_changed_linenos(unidiff_patch):
#     hunks = []
#     for patch in unidiff_patch:
#         for hunk in patch:
#             # for line in hunk:
#             # hunks.append([hunk.source_start, hunk.source_start + hunk.source_length - 1])
#             hunks.append(list(range(hunk.source_start, hunk.source_start + hunk.source_length)))
#     return hunks

def run_git_blame(latest_commit, file_path, line_number, path):
    result = run_command(f'git blame -L {line_number},{line_number} {latest_commit} -- {file_path}', path=path)
    # print(f'git blame -L {line_number},{line_number} {latest_commit} -- {file_path}')
    return result.stdout

def parse_git_blame_output(blame_output):
    lines = blame_output.splitlines()
    commit_hash_list = []
    for line in lines:
        if line.startswith("^"):
            line = line[1:]  # 忽略合并提交
        commit_hash_list.append(line.split()[0])
    return commit_hash_list

def get_line_content(unidiff_patch, lineno):
    for patch in unidiff_patch:
        for hunk in patch:
            for line in hunk:
                if line.source_line_no == lineno and line.is_removed:
                    return line.value.strip()

def get_add_place(diff_content, target_additions, target_lines):
    # target_lines = list(range(target_lines[0], target_lines[1]+1))
    patch_set = PatchSet(StringIO(diff_content))
    for patched_file in patch_set:
        in_target_block = False
        target_index = 0
        source_line_number = None
        for hunk in patched_file:
            source_line_number = hunk.source_start - 1
            for line in hunk:
                if line.is_added and not in_target_block:
                    if line.value.strip() == target_additions[target_index].strip() and line.target_line_no == target_lines[target_index]:
                        target_index += 1
                        if target_index == len(target_additions):
                            in_target_block = True
                            target_index = 0
                if in_target_block:
                    return source_line_number + 1
                if not line.is_added:
                    source_line_number += 1
    return None

def line_filter(line_numbers, diff_text):
    patch_set = PatchSet(StringIO(diff_text))
    added_lines = []
    for patched_file in patch_set:
        for hunk in patched_file:
            for line in hunk:
                if line.is_added:
                    target_line = line.target_line_no
                    if target_line in line_numbers:
                        added_lines.append(target_line)
    return added_lines

def filter_js_hunks(git_show_output):
    file_pattern = re.compile(r'^diff --git a/(.*) b/(.*)$')
    hunk_pattern = re.compile(r'^@@ .* @@')

    js_file = None
    result = []

    for line in git_show_output.splitlines():
        file_match = file_pattern.match(line)
        if file_match:
            js_file = file_match.group(1).endswith('.js')
            if js_file:
                result.append(line)
        elif js_file:
            result.append(line)
            if hunk_pattern.match(line):
                pass

    return '\n'.join(result)

def is_related_LLM(code_blockA, code_blockB, model):
    prompt = f'''Please understand the following two code blocks and analyze whether there is functional reuse between them. Output yes or no only and do not output other content.\n\nCode Block A:{code_blockA}\n\nCode Block B:{code_blockB}'''
    LLM_output = LLM_infer(prompt, model)

    # print('----------------prompt----------------')
    # print(prompt)
    # print('--------------------------------')
    # print('----------------output----------------')
    # print(LLM_output)
    # print('--------------------------------')
    if 'yes' in LLM_output.lower():
        return True
    elif 'no' in LLM_output.lower():
        return False
    assert True

def get_function_range(contentA, contentB, linosA):
    function_dictA = ast_parse(contentA)
    function_dictB = ast_parse(contentB)
    # (linea, lineb): [signature, function body]
    # print(linosA)
    # for k, v in function_dictA.items():
    #     print(k, v[0])
    map_function = get_map_function(linosA, function_dictA)
    if map_function is None:
        return [-1, -1]
    for k, v in function_dictB.items():
        if map_function == v[0]:
            return k
    return [-1, -1]
        
def get_map_function(linos, function_dict):
    target_functions = []
    for line in linos:
        target_function = None
        target_function_index = None
        for i in function_dict:
            if i[0] < line and i[1] >= line:
                if 'Anonymous Function' in function_dict[i][0] or 'Anonymous Arrow Function' in function_dict[i][0]:
                    continue
                query_function = ((i[0], i[1]), function_dict[i])
                if target_function is None:
                    target_function = query_function
                    target_function_index = i
                elif i[0] >= target_function_index[0] and i[1] <= target_function_index[1]:
                    target_function = query_function
                    target_function_index = i
        if target_function is not None:
            target_functions.append(target_function)
    for function in target_functions:
        if function is None:
            continue
        is_outermost = all(
            function[0][0] <= query_function[0][0] and 
            function[0][1] >= query_function[0][1]
            for query_function in target_functions
        )
        if is_outermost:
            return function[-1][0]

def find_added_lines(diff_content, line_content):
    # with open('temp/temp.diff', 'w') as f:
    #     print(diff_content, file=f)
    # print(f"###{line_content}###")
    # print(f"line_content:{line_content}")
    if line_content.strip() == '':
        return None
    # assert diff_content.count(line_content) == 2
    if diff_content.count(line_content) != 2:
        return None
    patch_set = PatchSet(StringIO(diff_content))
    for patched_file in patch_set:
        for hunk in patched_file:
            for line in hunk:
                if line.is_added and line.value == line_content:
                    return line.target_line_no

# def exactly_map_one_line(current_file_content, current_hunk_lines, function_range):
#     # print(current_file_content, current_hunk_lines)
#     # current_hunk_lines = [i.strip() for i in current_hunk_lines]
#     if function_range == [-1, -1]:
#         r = range(1, 100000)
#     else: r = range(function_range[0], function_range[1]+1)
#     lines = [i.strip() for i in current_file_content.splitlines()]
#     line_numbers = []
#     for i, line in enumerate(lines, start=1):
#         if i not in r:
#             continue
#         if line in current_hunk_lines:
#             for current_hunk_line in current_hunk_lines:
#                 similarity = SequenceMatcher(None, string_normalize(current_hunk_line), string_normalize(line)).ratio()
#                 if similarity > 0.95:
#                     line_numbers.append(i)
#     line_numbers.sort()
#     # line_numbers = (line_numbers[0], line_numbers[-1])
#     return line_numbers


def exactly_map(current_file_content, current_hunk_lines, function_range):
    # current_hunk_lines = [i.strip() for i in current_hunk_lines]
    if function_range == [-1, -1]:
        r = range(1, 100000)
    else: r = range(function_range[0], function_range[1]+1)
    lines = [i.strip() for i in current_file_content.splitlines()]
    line_numbers = []
    for i, line in enumerate(lines, start=1):
        if i not in r:
            continue
        # if line in current_hunk_lines:
        for current_hunk_line in current_hunk_lines:
            similarity = SequenceMatcher(None, string_normalize(current_hunk_line), string_normalize(line)).ratio()
            if similarity > 0.95:
                line_numbers.append(i)
    line_numbers.sort()
    # line_numbers = (line_numbers[0], line_numbers[-1])
    return line_numbers

if __name__ == '__main__':

    def similarity(s1, s2):
        matcher = SequenceMatcher(None, s1, s2)
        return matcher.ratio()
    s1 = r"""if (deep && copy && (isPlainObject(copy) || (copyIsArray = Array.isArray(copy))) {"""
    s2 = r"""if (deep && copy && (isPlainObject(copy) || (copyIsArray = Array.isArray(copy)))) {"""
    print(s1)
    print(f"Similarity: {similarity(s1, s2):.2f}")