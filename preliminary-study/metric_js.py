import sys
from pathlib import Path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE_DIR))
import subprocess
import fcntl
from concurrent.futures import ProcessPoolExecutor
import nltk
from nltk.translate.bleu_score import sentence_bleu, SmoothingFunction
from transformers import AutoTokenizer, AutoModel
import torch
from scipy.spatial.distance import cosine
from codebleu import calc_codebleu
from collections import defaultdict
from unidiff import PatchSet
from io import StringIO
from common_utils import run_command, is_commit1_earlier_than_commit2
import os
import re
from tree_sitter import Language, Parser
import tree_sitter_javascript
from datetime import datetime
import json
from Levenshtein import ratio
from difflib import SequenceMatcher
import tree_sitter_c




CODE_METRIC_LENGTH = 6

import logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S', 
)

regex = r'^https:\/\/github\.com\/[^\/]+\/[^\/]+\/commit\/[0-9a-f]+'
repo_root_path = '/data2/backport-repo'
data_root_path = './backport-data'
# result_file = './szz-result/szz_result-file-similarity.json'
result_file = './Javascript-cve.json'
commit_result_file = './szz-result/szz_result_commit.json'

class Metric:
    def __init__(self, cve_id, patch_commit, target_commit, target_lines, repo_path, language, patch_url=None):
        self.cve_id = cve_id
        self.patch_commit = patch_commit
        self.repo_path = repo_path
        self.target_commit = target_commit
        self.target_lines = target_lines
        self.patch_url = patch_url
        if language == "c":
            self.get_function_dict = get_function_dict_c
            # self.git_fetch()
            # self.target_lines = self._get_target_lines_c()
        else:
            self.get_function_dict = get_function_dict_javascript
        self.target_files = self._get_target_files(self.target_lines)
        self.target_functions = self._get_target_functions(self.target_lines)
        self.language = language
        self.url = f"https://www.github.com/{self.repo_path.split('/')[-1].replace('@', '/')}/commit/{self.patch_commit}"
        self.file_commit = self.get_file_commit()
        # self.output_commit_count()
        # self.output_commit_gap()
        self.output_file_content()
        self.output_function_content()
        if language == "javascript":
            self.result = self._get_result_js()
        elif language == "c":
            self.result = self._get_result_c()

    def output_commit_gap(self):
        time1 = get_commit_date(self.repo_path, self.patch_commit)
        time2 = get_commit_date(self.repo_path, self.target_commit)
        if time1 and time2:
            time_diff = abs(time1 - time2)
            self.time_gap = {"time_gap": time_diff.days}
        else:
            return None

    def output_commit_count(self):
        
        run_command(f'git rev-list --count {self.target_commit}..{self.patch_commit} -- ', path=self.repo_path)
        file_info = {}
        commit_sizes = {}
        for file_path in self.target_files:
            # try:

            log_command = [
                'git', 'log', f'{self.target_commit}..{self.patch_commit}', '--pretty=format:%H', '--', file_path
            ]
            result = subprocess.check_output(log_command, stderr=subprocess.STDOUT, cwd=self.repo_path)
            commits = result.decode('utf-8').strip().split('\n')
            if not commits or (len(commits) == 1 and not commits[0]):
                continue
            unique_commits = set(commits)
            for commit_id in unique_commits:
                if commit_id not in commit_sizes:
                    # 使用 `git show --stat --oneline` 获取 commit 的修改统计
                    # 格式如: '6f01f05 (HEAD -> main) fix: a bug\n file.c | 1 +-\n 1 file changed, 1 insertion(+), 1 deletion(-)'
                    show_command = ['git', 'show', '--stat=250', '--oneline', commit_id, '--', file_path]
                    show_result = subprocess.check_output(show_command, stderr=subprocess.STDOUT, cwd=self.repo_path)
                    show_output = show_result.decode('utf-8').strip()
                    
                    # 查找修改行数信息
                    lines = show_output.split('\n')
                    total_changes = 0
                    for line in lines:
                        if 'file changed' in line or 'files changed' in line:
                            parts = line.split(',')
                            for part in parts:
                                part = part.strip()
                                if 'insertion' in part:
                                    try:
                                        total_changes += int(part.split()[0])
                                    except (ValueError, IndexError):
                                        pass
                                elif 'deletion' in part:
                                    try:
                                        total_changes += int(part.split()[0])
                                    except (ValueError, IndexError):
                                        pass
                    commit_sizes[commit_id] = total_changes


            # except subprocess.CalledProcessError as e:
            #     print(f"Error processing file {file_path}: {e.output.decode('utf-8')}")
            #     continue
        total_commits = len(commit_sizes)
        average_commit_size = sum(commit_sizes.values()) / total_commits
        self.commit_info = {
            "total_commits": total_commits,
            "average_commit_size": average_commit_size,
            "commit_sizes": commit_sizes
        }



    def output_file_content(self):
        cve_id = self.cve_id
        self.file_items = []
        for index, target_file in enumerate(self.target_files):
            cve_item = {}
            cve_item['item_id'] = f'{cve_id}@{index}'
            cve_item['target_file_content'] = self.get_file_content(self.target_commit, target_file, self.repo_path)
            cve_item['patch_file_content'] = self.get_file_content(self.patch_commit, target_file, self.repo_path)
            self.file_items.append(cve_item)


    def output_function_content(self):
        cve_id = self.cve_id
        self.function_items = []
        for index, target_function in enumerate(self.target_functions):
            file_name, function_name = target_function
            result = run_command(f'git show {self.target_commit}:{file_name}', path=self.repo_path)
            if result.returncode:
                continue
            target_file_content = result.stdout
            patch_file_content = run_command(f'git show {self.patch_commit}:{file_name}', path=self.repo_path).stdout
            target_file_dict = self.get_function_dict(target_file_content)
            patch_file_dict = self.get_function_dict(patch_file_content)
            target_signature = self.find_function_in_dict(function_name, target_file_dict)
            patch_signature = self.find_function_in_dict(function_name, patch_file_dict)
            cve_item = {}
            cve_item['item_id'] = f'{cve_id}@{index}'
            if target_signature is None:
                continue
            cve_item['target_function_content'] = target_signature[-1]
            cve_item['patch_function_content'] = patch_signature[-1]
            self.function_items.append(cve_item)


        # cve_id = self.cve_id
        # self.cve_items = []
        # for index, target_file in enumerate(self.target_files):
        #     cve_item = {}
        #     cve_item['item_id'] = f'{cve_id}@{index}'
        #     cve_item['target_file_content'] = self.get_file_content(self.target_commit, target_file, self.repo_path)
        #     cve_item['patch_file_content'] = self.get_file_content(self.patch_commit, target_file, self.repo_path)
        #     self.cve_items.append(cve_item)

    def get_file_commit(self):
        for target_file in self.target_files:
            commit_list = self.get_commit_list(self.target_commit, self.patch_commit, target_file, self.repo_path)
            if len(commit_list) > 2:
                return commit_list

    def _get_result_js(self):
        stored_target_lines = {}
        for k, v in self.target_lines.items():
            stored_target_lines['@'.join(k)] = v
        metric_result = {"cve_id": self.cve_id, "repo": self.repo_path, "commit_id": self.patch_commit, "target_commit": self.target_commit, "url": self.url, "target_lines": stored_target_lines}
    
        metric_result.update(self.get_meta_metric())
        metric_result.update(self.get_file_metric())
        metric_result.update(self.get_function_metric())
        metric_result.update(self.get_all_file_similarity())
        return metric_result
    
    def git_fetch(self):
        r1 = run_command(f'git fetch origin {self.patch_commit}', path=self.repo_path)
        r2 = run_command(f'git fetch origin {self.target_commit}', path=self.repo_path)
        if r1.returncode != 0 or r2.returncode != 0:
            raise Exception("git fetch failed")

    def _get_result_c(self):
        stored_target_lines = {}
        for k, v in self.target_lines.items():
            stored_target_lines['@'.join(k)] = v
        metric_result = {"cve_id": self.cve_id, "repo": self.repo_path, "commit_id": self.patch_commit, "target_commit": self.target_commit, "url": self.url, "target_lines": stored_target_lines}
        metric_result.update(self.get_meta_metric())
        metric_result.update(self.get_file_metric())
        metric_result.update(self.get_function_metric())
        # metric_result.update(self.get_all_file_similarity())
        return metric_result

    def __str__(self):
        return f'{'---'*10}\ncve_id: {self.cve_id}\n patch_commit: {self.patch_commit}\n repo_path: {self.repo_path}\n vulnerable_commit: {self.target_commit}\n target_lines: {self.target_lines}\n target_files: {self.target_files}\n url: {self.url}\n{'---'*10}'

    def _get_target_lines_c(self):
        patch_text = run_command(f'curl -L {self.patch_url}.diff').stdout
        patch_set = PatchSet(StringIO(patch_text))
        target_lines = defaultdict(list)
        for patched_file in patch_set:
            if not is_c_sc(patched_file.path):
                continue
            self.has_c_file = True

            pre_file_content = run_command(f'git show {self.patch_commit}^:{patched_file.path}', path=self.repo_path).stdout
            if pre_file_content.strip() == '':
                run_command(f'git fetch origin {self.patch_commit}', path=self.repo_path).stdout
                pre_file_content = run_command(f'git show {self.patch_commit}^:{patched_file.path}', path=self.repo_path).stdout
            pre_function_dict = self.get_function_dict(pre_file_content)
            linenos = ([line.source_line_no for hunk in patched_file for line in hunk if line.is_removed])
            for lineno in linenos:
                line_function_localization = localize_function(lineno, pre_function_dict)
                key = (patched_file.path, line_function_localization)
                target_lines[key].append(lineno)

            post_file_content = run_command(f'git show {self.patch_commit}:{patched_file.path}', path=self.repo_path).stdout
            if post_file_content.strip() == '':
                run_command(f'git fetch origin {self.patch_commit}', path=self.repo_path).stdout
                post_file_content = run_command(f'git show {self.patch_commit}:{patched_file.path}', path=self.repo_path).stdout
            post_function_dict = self.get_function_dict(post_file_content)
            linenos = ([line.target_line_no for hunk in patched_file for line in hunk if line.is_added])
            for lineno in linenos:
                line_function_localization = localize_function(lineno, post_function_dict)
                key = (patched_file.path, line_function_localization)
                target_lines[key].append(lineno)    
        return target_lines


    def get_meta_metric(self):
        commit_time = self.commit_time_delta(self.target_commit, self.patch_commit, self.repo_path)
        commit_repo_count = self.commit_repo_count_delta(self.target_commit, self.patch_commit, self.repo_path)
        commit_file_count = self.commit_file_count_delta(self.target_commit, self.patch_commit, self.target_files, self.repo_path)
        dependency_change = self.dependency_change()
        license_change = self.license_change()
        file_list_change = self.file_list_change()
        file_list_similarity = None
        return {"commit_time": commit_time, "commit_repo_count": commit_repo_count, "commit_file_count": commit_file_count, "dependency_similarity": dependency_change, "license_change": license_change, "file_list_similiary": file_list_change, "file_list_content_similarity": file_list_similarity}

    def get_all_file_similarity(self):
        patched_file_list = self.get_file_list(self.patch_commit, self.repo_path)
        target_file_list = self.get_file_list(self.target_commit, self.repo_path)
        file_list_similarity = self.file_list_similarity(target_file_list, patched_file_list)
        return file_list_similarity

    def get_file_metric(self):
        target_file_list = [i for i in self.target_files if self.is_file_existed(self.target_commit, i, self.repo_path)]
        target_file_list_similarity = self.list_delta(self.target_files, target_file_list)
        target_file_list_content_similarity = self.file_list_similarity(self.target_files, self.target_files)
        return {"target_file_change": target_file_list_similarity, "target_file_list_similarity": target_file_list_content_similarity}

    def is_function_in_global(self, function_name):
        if function_name == 'global':
            return True
        return False

    def get_function_similarity(self, target_signature, patch_signature):
        if target_signature is None or patch_signature is None:
            return [0]*CODE_METRIC_LENGTH
        return self.content_similarity(target_signature[-1], patch_signature[-1])

    def is_function_name_changed(self, file_dict, function_name):
        return not any(i for i in file_dict.values() if i[0] == function_name)
       
    def is_signature_changed(self, target_signature, patch_signature):
        if target_signature is None or patch_signature is None:
            return True
        target_name, target_para, target_return, target_body = target_signature
        patch_name, patch_para, patch_return, patch_body = patch_signature
        if target_name == patch_name and target_para == patch_para and target_return == patch_return:
            return False
        return True

    def _function_metric(self, file_name, target_signature, patch_signature):
        if patch_signature is None:
            is_in_global = True
            is_name_changed = False
            is_signature_changed = False
            function_similarity = self.get_file_similarity(file_name)
        else:
            is_in_global = self.is_function_in_global(patch_signature[0])
            is_name_changed = True if target_signature is None else False
            is_signature_changed = self.is_signature_changed(target_signature, patch_signature)
            function_similarity = self.get_function_similarity(target_signature, patch_signature)
        return is_in_global, is_name_changed, is_signature_changed, function_similarity

    def get_function_metric(self):
        # target_function: (file_name, function_name)
        # target_function_dict: (start_line, end_line): (function_name, parameter, return, function body)
        function_metric = []
        for target_function in self.target_functions:
            file_name, function_name = target_function
            result = run_command(f'git show {self.target_commit}:{file_name}', path=self.repo_path)
            if result.returncode:
                continue
            target_file_content = result.stdout
            patch_file_content = run_command(f'git show {self.patch_commit}:{file_name}', path=self.repo_path).stdout
            target_file_dict = self.get_function_dict(target_file_content)
            patch_file_dict = self.get_function_dict(patch_file_content)
            target_signature = self.find_function_in_dict(function_name, target_file_dict)
            patch_signature = self.find_function_in_dict(function_name, patch_file_dict)
            function_metric.append(self._function_metric(file_name, target_signature, patch_signature))
        return {"function_metric": function_metric}
        logging.debug(f"function_metric")
        logging.debug(function_metric)

    def _get_target_functions(self, target_lines):
        return [i for i in target_lines.keys()]

    def _get_target_files(self, target_lines):
        return [i[0] for i in target_lines.keys()]

    def dependency_change(self):
        target_dependencies = self.parse_dependency(self.target_commit, self.repo_path)
        patch_dependencies = self.parse_dependency(self.patch_commit, self.repo_path)
        return self.list_delta(target_dependencies, patch_dependencies)
    
    def license_change(self):
        target_license = self.parse_license(self.target_commit, self.repo_path)
        patch_license = self.parse_license(self.patch_commit, self.repo_path)
        return True if target_license != patch_license else False

    def file_list_change(self):
        target_file_list = self.get_file_list(self.target_commit, self.repo_path)
        patch_file_list = self.get_file_list(self.patch_commit, self.repo_path)
        return self.list_delta(target_file_list, patch_file_list)
    
    def file_list_similarity(self, file_listA, file_listB):
        file_list_union = list(set(file_listA).union(set(file_listB)))
        file_list_intersection = list(set(file_listA).intersection(set(file_listB)))
        file_similarity_list = [self.get_file_similarity(file) for file in file_list_intersection]
        return file_similarity_list
        if not file_similarity_list:
            return [0]*CODE_METRIC_LENGTH
        return [sum([i[j] for i in file_similarity_list])/len(file_list_union) for j in range(CODE_METRIC_LENGTH)]

    def get_file_similarity(self, file_path):
        target_file_content = self.get_file_content(self.target_commit, file_path, self.repo_path)
        patch_file_content = self.get_file_content(self.patch_commit, file_path, self.repo_path)
        return self.content_similarity(target_file_content, patch_file_content)
    
    @staticmethod
    def find_function_in_dict(function_name, function_dict):
        for key, value in function_dict.items():
            if value[0] == function_name:
                return value
        return None

    def content_similarity(self, contentA, contentB):
        edit_distance = self.edit_distance(contentA, contentB)
        jaccard_similarity = self.jaccard_similarity(contentA, contentB)
        line_diff = self.line_diff_ratio(contentA, contentB)
        bleu = self.calculate_bleu(contentA, contentB)
        code_bleu = self.codebleu(contentA, contentB, self.language)
        # code_bert = calculate_similarity(contentA, contentB)
        code_bert = 0
        return edit_distance, jaccard_similarity, line_diff, bleu, code_bleu, code_bert

    @staticmethod
    def line_diff_ratio(contentA, contentB):
        return SequenceMatcher(None, contentA.splitlines(), contentB.splitlines()).ratio()

    @staticmethod
    def commit_line_diff_ratio(commitA, commitB, file_path, repo_path):
        result = run_command(f'git diff --numstat {commitA} {commitB} -- {file_path}', path=repo_path).stdout
        if '-' in result:
            return 1
        try:
            add_line, delete_line, _ = result.split('\t')
        except ValueError:
            return 1
        add_line = int(add_line)
        delete_line = int(delete_line)
        commitA_line = Metric.get_file_line_count(commitA, file_path, repo_path)
        commitB_line = Metric.get_file_line_count(commitB, file_path, repo_path)
        return 1-(add_line + delete_line) / (commitA_line + commitB_line + commitA_line - delete_line)

    @staticmethod
    def get_file_content(commit, file_path, repo_path):
        result = run_command(f'git show {commit}:{file_path}', path=repo_path)
        if result.returncode:
            return ''
        return result.stdout

    @staticmethod
    def get_file_line_count(commit, file_path, repo_path):
        result = run_command(f'git show {commit}:{file_path}', path=repo_path)
        if result.returncode:
            return 0
        return len(result.stdout.splitlines())

    @staticmethod
    def edit_distance(contentA, contentB):
        return ratio(contentA, contentB)
    
    @staticmethod
    def jaccard_similarity(contentA, contentB):
        setA = set(contentA.split())
        setB = set(contentB.split())
        return Metric.list_delta(setA, setB)

    @staticmethod
    def get_file_list(commit, repo_path):
        file_list = run_command(f'git ls-tree -r --name-only {commit}', path=repo_path)
        return file_list.stdout.strip().split('\n')

    @staticmethod
    def is_file_existed(commit, file_path, repo_path):
        return False if run_command(f'git cat-file -e {commit}:{file_path}', path=repo_path).returncode else True

    @staticmethod
    def list_delta(listA, listB):
        set1 = set(listA)
        set2 = set(listB)
        intersection = set1.intersection(set2)
        union = set1.union(set2)
        if not union:
            return 1.0
        return len(intersection) / len(union)

    @staticmethod
    def commit_time_delta(commitA, commitB, repo_path):
        def get_commit_date(commit):
            result = run_command(f'git show -s --format=%ci {commit}', path=repo_path)
            return result.stdout.split()[0]
        date_a = datetime.fromisoformat(get_commit_date(commitA))
        date_b = datetime.fromisoformat(get_commit_date(commitB))
        return (date_b - date_a).days

    @staticmethod
    def commit_repo_count_delta(commitA, commitB, repo_path):
        return int(run_command(f'git rev-list {commitA}..{commitB} --count', path=repo_path).stdout.strip())

    @staticmethod
    def commit_file_count_delta(commitA, commitB, files, repo_path):
        file_counts = [run_command(f'git rev-list {commitA}..{commitB} --count -- "{target_file}"', path=repo_path).stdout.strip() for target_file in files]
        if len(file_counts) == 0:
            return 0
        return sum(int(count) for count in file_counts)/len(file_counts)

    @staticmethod
    def get_commit_list(commitA, commitB, file, repo_path):
        return run_command(f'git rev-list {commitA}..{commitB} -- "{file}"', path=repo_path).stdout.strip().split('\n')

    @staticmethod
    def parse_dependency(commit_id, repo_path):
        result = run_command(f"git show {commit_id}:package.json", path=repo_path)
        if result.returncode:
            return []
        try:
            package_json = json.loads(result.stdout)
        except json.decoder.JSONDecodeError:
            return []
        dep_types = ['dependencies', 'devDependencies', 
                    'peerDependencies', 'optionalDependencies']
        try:
            dependencies = [
                f"{package}:{version}"
                for dep_type in dep_types
                if dep_type in package_json
                for package, version in package_json[dep_type].items()
            ]
        except AttributeError:
            return []
        return dependencies

    @staticmethod
    def parse_license(commit_id, repo_path):
        result = run_command(f"git show {commit_id}:package.json", path=repo_path)
        if result.returncode:
            return 'Unknown'
        try:
            package_json = json.loads(result.stdout)
        except json.decoder.JSONDecodeError:
            return 'Unknown'
        license = package_json['license'] if 'license' in package_json else 'Unknown'
        return license

    @staticmethod
    def codebleu(contentA, contentB, language):
        result = calc_codebleu(
            references=[contentA],
            predictions=[contentB],
            lang=language,
            weights=(0.25, 0.25, 0.25, 0.25)
        )
        return result['codebleu']
    
    @staticmethod
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


class SZZ:
    # input: project path, patch_id
    def __init__(self, cve_id, patch_url):
        self.cve_id = cve_id
        logging.debug(cve_id)
        self.patch_url = self._extract_patch_url(patch_url)
        self.has_js_file = False
        self.repo_path = self._build_repo_path(patch_url, repo_root_path)
        self.commit_id = self.patch_url.split('/')[-1]
        self.target_lines = self.get_target_lines()
        self.target_commit = self.git_blame()

    def _extract_patch_url(self, patch_url):
        try:
            return re.match(regex, patch_url).group()
        except AttributeError:
            return None

    def _build_repo_path(self, patch_url, repo_root_path):
        splited_target = patch_url.split('/')
        if len(splited_target) < 5:
            raise ValueError(f"Patch URL doesn't contain owner/repo information: {patch_url}")
        owner_repo = f"{splited_target[3]}@{splited_target[4]}"
        if not os.path.exists(os.path.join(repo_root_path, owner_repo)):
            owner_repo = splited_target[4]
        return os.path.join(repo_root_path, owner_repo)

    # input: untangled patch
    # output: line number
    def get_target_lines(self):
        patch_text = run_command(f'curl -L {self.patch_url}.diff').stdout
        patch_set = PatchSet(StringIO(patch_text))
        target_lines = defaultdict(list)
        for patched_file in patch_set:
            # if not is_js_sc(patched_file.path):
            #     continue
            if not is_c_sc(patched_file.path):
                continue
            self.has_js_file = True
            file_content = run_command(f'git show {self.commit_id}^:{patched_file.path}', path=self.repo_path).stdout
            # function_dict = get_function_dict_javascript(file_content)
            function_dict = get_function_dict_c(file_content)
            # print(patched_file.path+'\n')
            # for k, v in function_dict.items():
            #     print(k, v[0])
            linenos = ([line.source_line_no for hunk in patched_file for line in hunk if line.is_removed])
            for lineno in linenos:
                line_function_localization = localize_function(lineno, function_dict)
                key = (patched_file.path, line_function_localization)
                target_lines[key].append(lineno)
        # logging.debug(f"target_lines: {target_lines}")
        return target_lines

    def git_blame(self):
        commit_ids = []
        for (path, function_name), linenos in self.target_lines.items():
            for lineno in linenos:
                blame_result = self._run_git_blame(lineno, path)
                if blame_result is None:
                    continue
                # logging.debug(f"lineno: {lineno} - result: {blame_result}")
                current_commit_ids = parse_git_blame_output(blame_result)
                commit_ids.extend(current_commit_ids)
        current_commit = None
        for commit_hash in commit_ids:
            if current_commit is None or not is_commit1_earlier_than_commit2(current_commit, commit_hash, self.repo_path):
                current_commit = commit_hash

        # if current_commit is None:
        #     with open('./szz-result/szz_failed_case.txt', 'a') as f:
        #         print(f"{self.cve_id} - {self.has_js_file} - {self.patch_url}", file=f)

        return current_commit

    def _run_git_blame(self, lineno, path):
        blame_result = run_command(f'git blame -L {lineno},{lineno} {self.commit_id}^ -- {path}', path=self.repo_path)
        if blame_result.returncode:
            return None
        return blame_result.stdout

def localize_function(target_line, function_dict):
    current_range = None
    result_function_name = 'global'
    for range, function_signatures in function_dict.items():
        function_name = function_signatures[0]
        start_line, end_line = range
        if start_line <= target_line <= end_line:
            if result_function_name in ('Anonymous Function', 'global'):
                result_function_name = function_name
                current_range = range
            elif current_range[0] <= range[0] and current_range[1] >= range[1]:
                result_function_name = function_name
                current_range = range
    return result_function_name

def get_function_dict(source_content):
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
            source_node = node
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
    return functions

def get_function_dict_c(source_content):
    source_content = source_content.encode('utf-8')
    C_LANGUAGE = Language(tree_sitter_c.language())
    parser = Parser(C_LANGUAGE)
    tree = parser.parse(source_content)

    FUNCTION_QUERY = C_LANGUAGE.query("""
(function_definition
  type: (_) @function_type
  declarator: (function_declarator
    declarator: (identifier) @func_name
    parameters: (parameter_list) @params                         
    )
  body: (compound_statement) @func_body) @func
    """)
    functions = []

    for capture_struct in FUNCTION_QUERY.captures(tree.root_node):
        # print(capture_struct)
        node = capture_struct[0]
        if node.type == "function_definition":
            func_info = {
                "name": None,
                "parameter": None,
                "type": source_content[node.children[0].start_byte:node.children[0].end_byte].decode(), 
                "start_line": node.start_point[0] + 1,
                "end_line": node.end_point[0] + 1,
                "return": None,
                "body": None
            }
            for child in node.children:
                if child.type == "function_declarator":
                    for subchild in child.children:
                        if subchild.type == "identifier":
                            func_info["name"] = source_content[
                                subchild.start_byte:subchild.end_byte
                            ].decode()
                        elif subchild.type == "parameter_list":
                            func_info["parameter"] = ' '.join(source_content[
                                subchild.start_byte:subchild.end_byte
                            ].decode().split())
                elif child.type == "compound_statement":
                    func_info["body"] = source_content[
                        child.start_byte:child.end_byte
                    ].decode()
            query = C_LANGUAGE.query("(return_statement (expression) @expr)")
            captures = query.captures(node)
            for capture in captures:
                expr_node = capture[0]
                start, end = expr_node.start_byte, expr_node.end_byte
                func_info["return"] = source_content[start:end].decode('utf8')
            functions.append(func_info)
    function_range = {}
    for function in functions:
        function_range[(function['start_line'], function['end_line'])] = (function['name'], function['parameter'], f"{str(function['type'])}@{str(function['return'])}", function['body'])
    return function_range


def get_function_dict_javascript(source_content):
    source_content = source_content.encode('utf-8')
    JS_LANGUAGE = Language(tree_sitter_javascript.language())
    parser = Parser(JS_LANGUAGE)
    tree = parser.parse(source_content)

    function_ranges = {}
    def extract_function_signatures(node, code, function_ranges):
        for child in node.children:
            extract_function_signatures(child, source_content, function_ranges)
        if node.type not in ('function_declaration', 'function_expression', 'arrow_function', 'method_definition'):
            return function_ranges
        parameters_node = node.child_by_field_name('parameters')
        parameters = code[parameters_node.start_byte:parameters_node.end_byte].decode('utf8') if parameters_node else ''
        query = JS_LANGUAGE.query("(return_statement (expression) @expr)")
        captures = query.captures(node)
        return_value = ''
        for capture in captures:
            expr_node = capture[0]
            start_line, end_line = expr_node.start_point[0]+1, expr_node.end_point[0]+1
            if any(start_line >= s and end_line <= e for s, e in function_ranges.keys()):
                continue
            start, end = expr_node.start_byte, expr_node.end_byte
            return_value = code[start:end].decode('utf8')
        if node.type == 'function_declaration':
            function_name_node = node.child_by_field_name('name')
            if function_name_node:
                function_name = code[function_name_node.start_byte:function_name_node.end_byte].decode('utf8')
                function_body = code[node.start_byte:node.end_byte].decode('utf8')
                start_line, end_line = node.start_point[0]+1, node.end_point[0]+1
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
            source_node = node
            function_body = code[source_node.start_byte:source_node.end_byte].decode('utf8')
            start_line, end_line = source_node.start_point[0]+1, source_node.end_point[0]+1
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
        elif node.type == 'method_definition':
            function_body = code[node.start_byte:node.end_byte].decode('utf8')
            method_name_node = node.child_by_field_name('name')
            if method_name_node:
                function_name = code[method_name_node.start_byte:method_name_node.end_byte].decode('utf8')
                start_line, end_line = node.start_point[0]+1, node.end_point[0]+1
        function_ranges[(start_line, end_line)] = (function_name, parameters, return_value, function_body)
        return function_ranges
    functions = extract_function_signatures(tree.root_node, source_content, function_ranges)
    # for k, v in functions.items():
    #     print(k, v[:-1])
    return functions


def get_code_embedding(code):
    device = f"cuda:{os.getpid() % torch.cuda.device_count()}"
    # device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    tokenizer = AutoTokenizer.from_pretrained("./codebert-base")
    model = AutoModel.from_pretrained("./codebert-base").to(device)
    inputs = tokenizer(code, return_tensors="pt", truncation=True, max_length=512)
    inputs = {k: v.to(device) for k, v in inputs.items()} 
    with torch.no_grad():
        outputs = model(**inputs)
    embeddings = outputs.last_hidden_state[:, 0, :]    
    return embeddings.cpu()

def calculate_similarity(code1, code2):
    embedding1 = get_code_embedding(code1)
    embedding2 = get_code_embedding(code2)
    similarity = 1 - cosine(embedding1[0], embedding2[0])   
    return float(similarity)

def parse_git_blame_output(blame_output):
    lines = blame_output.splitlines()
    line = lines[0]
    commit_hash_list = []
    if line.startswith("^"):
        line = line[1:]
    commit_hash_list.append(line.split()[0])
    return commit_hash_list

def load_data():
    data_path = os.path.join(data_root_path, 'merged-data.csv')
    loaded_data = []
    with open(data_path) as f:
        lines = f.readlines()
    for line in lines:
        splited_line = line.strip().split(',')
        cve_id = splited_line[0]
        patch_urls = splited_line[1:]
        loaded_data.append([cve_id, patch_urls])        
    return loaded_data

def load_target_data_javascript():
    data_path = os.path.join(data_root_path, 'merged-dataV1.csv')
    # data_path = os.path.join(data_root_path, 'test.csv')
    loaded_data = []
    with open(data_path) as f:
        lines = f.readlines()
    for line in lines:
        splited_line = line.strip().split(' ')
        cve_id = splited_line[0]
        patch_urls = splited_line[1]
        loaded_data.append([cve_id, patch_urls])        
    return loaded_data

# 1. 先从patch list中选择一个patch
# 2. 如果patch中没有修改，则关注NVD中的漏洞范围
def select_most_changed_patch(data):
    written_path = os.path.join(data_root_path, 'merged-dataV1.csv')
    existed_data = open(written_path).read()
    for cve_item in data:        
        cve = cve_item[0]
        if cve in existed_data:
            continue
        logging.debug(f'processing {cve}...')
        patch_list = cve_item[1]
        if len(patch_list) == 1:
            best_patch = patch_list[0]
        else:
            best_patch = max(
                patch_list,
                key=lambda url: get_path_count(url),
            )
        with open(written_path, 'a') as f:
            print(cve, best_patch, file=f)

def is_js_sc(path):
    if 'min.js' in path or 'test' in path or '.json' in path or '.ts' in path or ('.js' not in path and '.mjs' not in path):
        return False
    return True

def is_c_sc(path):
    if '.c' not in path:
        return False
    return True

def get_path_count(patch_url):
    patch_text_url = patch_url+'.diff'
    patch_text = run_command(f'curl -L {patch_text_url}').stdout
    patch_set = PatchSet(StringIO(patch_text))
    return sum(1 for patched_file in patch_set if is_js_sc(patched_file.path))
            

# git install and rename
def remove_duplicated_repo_name(data):
    temp_data = []
    for i in data:
        target = i[1][0]
        splited_target = target.split('/')
        owner_repo = splited_target[3] + '/' + splited_target[4]
        repo = splited_target[4]
        repo_url = '/'.join(splited_target[:5])
        temp_data.append((owner_repo, repo, repo_url))
    temp_data = list(set(temp_data))
    for i in temp_data:
        temp_target_path = os.path.join(repo_root_path, i[1])
        target_path = os.path.join(repo_root_path, i[0].replace('/', '@'))
        if not os.path.exists(target_path):
            print(i)
        # if os.path.exists(target_path) and len(os.listdir(target_path)) == 0:
        #     run_command(f'rm -r {target_path}', path=root_path)
        # if os.path.exists(target_path):
        #     continue
        # if not os.path.exists(temp_target_path):
        #     print(f'git clone {i[2]} {i[0].replace('/', '@')}')
        #     run_command(f'GIT_TERMINAL_PROMPT=0 git clone {i[2].replace('github.com', 'github.com')} {i[0].replace('/', '@')}', path=root_path)
        #     continue
        # else:
        #     remote_output = run_command('git remote -v', path=temp_target_path).stdout
        #     if i[1] in remote_output:
        #         print(f'mv {i[1]} {i[0].replace('/', '@')}')
        #         run_command(f'mv {i[1]} {i[0].replace('/', '@')}', path=root_path)
        #     else:
        #         print(f'git clone {i[2]} {i[0].replace('/', '@')}')
        #         run_command(f'GIT_TERMINAL_PROMPT=0 git clone {i[2].replace('github.com', 'github.com')} {i[0].replace('/', '@')}', path=root_path)


def git_clone_from_patch():
    with open('./temp/szz-no-repo.txt') as f:
        lines = [i.strip() for i in f.readlines()]
    for line in lines:
        logging.debug(f'processing {line}...')
        splited_target = line.split('/')
        owner_repo = splited_target[3] + '@' + splited_target[4]
        repo_url = '/'.join(splited_target[:5])
        run_command(f'git clone {repo_url} {owner_repo}', path=repo_root_path)

def load_result_javascript(file_path=result_file):
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        with open(file_path, 'w') as f:
            json.dump([], f)
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return data

def write_result_javascript(result, file_path=result_file):
    data = load_result_javascript()
    if isinstance(result, list):
        data.extend(result)
    else:
        data.append(result)
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

def write_result_lock(result, file_path=result_file):
    with open(file_path, 'a+', encoding='utf-8') as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        f.seek(0)
        if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
            json.dump([], f)
        data = json.load(f)
        if isinstance(result, list):
            data.extend(result)
        else:
            data.append(result)
        f.seek(0)
        f.truncate()
        json.dump(data, f, ensure_ascii=False, indent=4)

def szz_main():
    data = load_target_data_javascript()
    flag = True
    for cve_item in data:
        cve = cve_item[0]
        patch = cve_item[1]
        if cve == 'CVE-2021-43785':
            flag = True
        if flag:
            szz_item = SZZ(cve, patch)

def get_commit_date(repo_path, commit_sha):
    try:
        command = ['git', '-C', repo_path, 'log', '-1', '--pretty=%ct', commit_sha]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        timestamp_str = result.stdout.strip()
        timestamp = int(timestamp_str)
        return datetime.fromtimestamp(timestamp)
    except (subprocess.CalledProcessError, ValueError) as e:
        return None


def commit_metric_main():
    data = load_target_data_javascript()
    # results = load_result_javascript()
    coped_cve_content = open('./szz-result/szz_failed_case.txt').read()
    # cves = [i['cve_id'] for i in results]
    for cve_item in data:
        if cve_item[0] in coped_cve_content:
            continue
        process_commit_item(cve_item)


def commit_metric_main_multiprocessing():
    data = load_target_data_javascript()
    # results = load_result_javascript()
    coped_cve_content = open('./szz-result/szz_failed_case.txt').read()
    # cves = [i['cve_id'] for i in results]
    tasks = []
    for cve_item in data:
        if cve_item[0] in coped_cve_content:
            continue
        tasks.append(cve_item)
    if not tasks:
        logging.info("All CVEs already processed.")
        return
    with ProcessPoolExecutor(max_workers=16) as executor:
        result = [executor.submit(process_commit_item, task) for task in tasks]

def process_commit_item(cve_item):
    cve = cve_item[0]
    patch = cve_item[1]
    logging.info(f'Processing {cve} in process {os.getpid()}...')
    szz_item = SZZ(cve, patch)
    if szz_item.target_commit is None:
        logging.warning(f'Skipping {cve}: target_commit not found')
        return
    cve_item = Metric(
        cve, 
        szz_item.commit_id, 
        szz_item.target_commit, 
        szz_item.target_lines, 
        szz_item.repo_path, 
        "javascript"
    )
    commit_list = cve_item.file_commit
    if commit_list is None:
        return
    i = 0
    j = 1
    print(commit_list)

    while j != len(commit_list) - 1:
        commit_id1 = commit_list[i]
        commit_id2 = commit_list[j]
        file_item = Metric(
            cve, 
            commit_id2, 
            commit_id1, 
            szz_item.target_lines, 
            szz_item.repo_path, 
            "javascript"
        )
        # write_result_lock(file_item.result, file_path=commit_result_file)
        write_result_lock(file_item.file_items, file_path='js-commit-file.json')
        write_result_lock(file_item.function_items, file_path='js-commit-function.json')
        i+=1
        j+=1



def metric_main():
    data = load_target_data_javascript()
    results = load_result_javascript()
    coped_cve_content = open('./szz-result/szz_failed_case.txt').read()
    cves = [i['cve_id'] for i in results]
    for cve_item in data:
        cve = cve_item[0]
        # if cve != "CVE-2024-45590":
        # if cve in cves or cve in coped_cve_content:
        #     continue
        process_cve_item(cve_item)

def process_cve_item(cve_item):
    cve = cve_item[0]
    patch = cve_item[1]
    logging.info(f'Processing {cve} in process {os.getpid()}...')
    szz_item = SZZ(cve, patch)
    if szz_item.target_commit is None:
        logging.warning(f'Skipping {cve}: target_commit not found')
        return None
    metric_item = Metric(
        cve, 
        szz_item.commit_id, 
        szz_item.target_commit, 
        szz_item.target_lines, 
        szz_item.repo_path, 
        "javascript"
    )
    write_result_lock(metric_item.time_gap, file_path='./motivation/js-commit-time.json')
    # write_result_lock(metric_item.file_items, file_path='js-file.json')
    # write_result_lock(metric_item.function_items, file_path='js-function.json')

def metric_main_multiprocessing():
    data = load_target_data_javascript()
    results = load_result_javascript()
    coped_cve_content = open('./szz-result/szz_failed_case.txt').read()
    existing_cves = {i['cve_id'] for i in results}
    tasks = []
    for cve_item in data:
        cve = cve_item[0]
        # if cve in existing_cves or cve in coped_cve_content:
        #     continue
        tasks.append(cve_item)
    # for task in tasks:
    #     process_cve_item(task)

    if not tasks:
        logging.info("All CVEs already processed.")
        return
    with ProcessPoolExecutor(max_workers=16) as executor:
        result = [executor.submit(process_cve_item, task) for task in tasks]



if __name__ == '__main__':
    metric_main_multiprocessing()
    # commit_metric_main_multiprocessing()
