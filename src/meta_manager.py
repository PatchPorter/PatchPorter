from common_utils import run_command, is_commit1_earlier_than_commit2, count_file_lines
import git
import json
import requests
import os
import re
from collections import defaultdict
from unidiff import PatchSet
import unidiff
from result_analyzer import get_porting_type_info

class MetaManager:
    def __init__(self, project):
        self.project = project

        self.prj_path = project.prj_path
        self.prj_name = project.prj_name
        
        self.npm_path = project.npm_path
        self.npm_prj_path = project.npm_prj_path
        
        self.patch_path = project.patch_path
        self.patch_url = project.patch_url
        self.patch_id = project.patch_id
        self.final_patch_path = project.final_patch_path
        self.target_file_name = project.target_file_name
        self.target_file_path = project.target_file_path
        
        self.version_map_path = project.version_map_path
        self.vul_version_map_path = project.vul_version_map_path
        self.vul_commit_version_map = project.vul_commit_version_map

        self.target_path = os.path.join(project.prj_path, 'target')

    def rm_dir(self, path):
        run_command(f'rm {path}/*', path=self.prj_path)

    def output_challenge_version(self):
        challenge_version = self.project.get_challenge_version()
        print(challenge_version, self.prj_path)

    def store_challenge_version(self):
        challenge_version = self.project.get_challenge_version()
        if challenge_version is None:
            print(f'{self.prj_path} has no challenge version')
        with open(self.project.challenge_version_path, 'w') as f:
            f.write(challenge_version)

    def output_prompt(self, model):
        challenge_version = self.project.get_challenge_version()
        prompt_path = os.path.join(self.prj_path, 'prompt-refined')
        run_command(f'mkdir -p {prompt_path}', path=self.prj_path)
        output_file_path = os.path.join(prompt_path, f'{model}-prompt.txt')
        # with open(output_file_path, 'w') as f: ...
        with open(os.path.join(self.project.result_path, f'{model}-result.txt')) as f:
            results = [i.strip().split(' ') for i in f.readlines()]
        for file_name in os.listdir(self.project.prompt_path):
            # if 'json' not in file_name or not file_name.startswith(challenge_version):
            #     continue
            # if 'deepseek-api@' not in file_name:
            #     continue
            # if 'file' in file_name or 'similarity' in file_name:
            #     continue
            if file_name.split('@')[1] != model:
                continue
            with open(os.path.join(self.project.prompt_path, file_name)) as f:
                json_content = json.load(f)
            prompts = json_content['prompt']
            llm_output = {}
            for k, v in json_content.items():
                if 'output' in k:
                    llm = k[:k.find('-output')]
                    llm_output[llm] = v
            with open(output_file_path, 'w') as f:
                f.write(file_name+'\n')
                for i in range(len(prompts)):
                    current_prompt = prompts[i]['prompt']
                    f.write(f"{current_prompt}")
                    for k, v in llm_output.items():
                        f.write('\n'+'-'*30+'\n')
                        f.write(f'{k}: ')
                        for result in results:
                            if result[2] in k and result[-1] in file_name:
                                f.write(f"{result[0]}\n")
                                break
                        f.write(v[i]+'\n')
                    f.write('*'*50+'\n')
                f.write('#'*100+'\n')
                
    def match_cve(self, cve_id):
        if self.project.cve_id == cve_id:
            print(cve_id, self.project.prj_path, self.project.patch_url)

    def output_target_files(self):
        # if not os.path.exists(self.target_path):
        run_command(f'rm -rf {self.target_path}')
        run_command(f'mkdir {self.target_path}')
        for commit_id, version in self.project.vul_commit_version_map.items():
            self.project.checkout(commit_id)
            git_apply_result = run_command('git apply ../../final-patch.diff', path=self.npm_prj_path).stderr
            if 'not apply' not in git_apply_result:
                continue
            patch_fuzz_result = run_command('patch -p1 --fuzz=10 < ../../final-patch.diff', path=self.npm_prj_path).stdout
            if 'FAILED' not in patch_fuzz_result:
                continue
            run_command('git checkout .', path=self.npm_prj_path)
            target_file_path = os.path.join(self.target_path, f'{version}-{self.target_file_name}')
            with open(target_file_path, 'w') as f:
                try:
                    with open(self.target_file_path) as f_read:
                        f.write(f_read.read())
                except FileNotFoundError:
                    continue

    def bk_final_patch(self):
        run_command(f'cp {self.final_patch_path} {self.final_patch_path}.bk', path=self.prj_path)

    def bk_prompt(self):
        for file_name in os.listdir(self.project.prompt_path):
            file_path = os.path.join(self.project.prompt_path, file_name)
            if file_name.endswith('json.bk'):
                print(file_path)
                # print(f'mv {file_path} {file_path[:-3]}')
                run_command(f'mv {file_path} {file_path[:-3]}', path=self.prj_path)

    def print_info(self):
        for i in os.listdir(self.prj_path):
            if i.endswith('.test.js'):
                file_path = os.path.join(self.prj_path, i)
                with open(file_path) as f:
                    content = f.read()
                    if '} catch (error) {}' in content:
                        print(file_path)

    def test_pre_post_patch(self):
        self.project.checkout_before_patch()
        pre_result = self.project.jest()
        self.project.checkout_patch()
        post_result = self.project.jest()
        print(self.prj_path)
        print(post_result, pre_result)

    def output_line_chunk_line(self):
        before_line_count = self.count_changed_lines_unidiff(self.project.patch_path)
        after_line_count = self.count_changed_lines_unidiff(self.project.final_patch_path)
        before_chunk_count = self.get_chunk_counts(self.project.patch_path)
        after_chunk_count = self.get_chunk_counts(self.project.final_patch_path)
        type_dict = get_porting_type_info()
        with open('./table_data.json', 'r', encoding='utf-8') as file:
            data = json.load(file)
        data.append({
            'prj_path': self.prj_path.split('/')[-1],
            'before_line_count': before_line_count,
            'after_line_count': after_line_count,
            'before_chunk_count': before_chunk_count,
            'after_chunk_count': after_chunk_count,
            'type': type_dict[self.prj_path.split('/')[-1]]
        })
        with open('./table_data.json', 'w', encoding='utf-8') as file:
            json.dump(data, file, indent=4)
        # print(self.prj_path, before_line_count, after_line_count, before_chunk_count, after_chunk_count, type_dict[self.prj_path.split('/')[-1]])

    def count_changed_lines_unidiff(self, path):
        added_lines = 0
        removed_lines = 0
        try:
            patch_set = PatchSet.from_filename(path, encoding='utf-8')
        except Exception as e:
            return 0, 0


        for patched_file in patch_set:
            added_lines += patched_file.added
            removed_lines += patched_file.removed
        return added_lines + removed_lines

    def output_patch_target_file(self):
        target_file_path = os.path.join(self.prj_path, f'target.js')
        target_commit = self.project.get_challenge_commit()
        target_file_content = run_command(f'git show {target_commit}:{self.project.unidiff_patch[0].path}', path=self.project.npm_prj_path).stdout
        pre_file_path = os.path.join(self.prj_path, 'pre.js')
        pre_file_content = run_command(f'git show {self.project.patch_id}^:{self.project.unidiff_patch[0].path}', path=self.project.npm_prj_path).stdout
        post_file_path = os.path.join(self.prj_path, 'post.js')
        post_file_content = run_command(f'git show {self.project.patch_id}:{self.project.unidiff_patch[0].path}', path=self.project.npm_prj_path).stdout
        with open(pre_file_path, 'w') as f:
            f.write(pre_file_content)
        with open(post_file_path, 'w') as f:
            f.write(post_file_content)
        with open(target_file_path, 'w') as f:
            f.write(target_file_content)
        if any(i for i in [pre_file_path, post_file_path, target_file_path] if os.path.getsize(i) == 0):
            print(self.prj_path, 'error')

    def cp_patch_target_file(self):
        run_command(f'cp {self.project.patch_path} ./patches/{self.project.prj_id}.diff')
        run_command(f'cp {self.prj_path}/target.js ./patches/{self.project.prj_id}.js')

    def list_target_file(self):
        challenge_version = self.project.get_challenge_version()
        commit_id = self.project.find_commit_from_version(challenge_version)
        self.project.checkout(commit_id)
        run_command(f'cp {self.target_file_path} {self.prj_path}')

    def count_file_length(self, granularity):
        file_path = f'./case-analysis/{granularity}-case_analysis.txt'
        flag = True
        challenge_version = self.project.get_challenge_version()
        if challenge_version is None:
            return 
        with open(self.project.result_file_path) as f:
            lines = [i.strip() for i in f.readlines()]
        for line in lines:
            if f'deepseek-api {granularity}' in line:
                if 'False' in line:
                    flag = False
                elif 'True' in line:
                    flag = True
                else: flag = None
        for file_name in os.listdir(os.path.join(self.project.output_path)):
            if f'deepseek-api-{granularity}' in file_name and challenge_version in file_name:
                result = (flag, self.prj_path)
                with open(file_path, 'a') as f:
                    print(result, file=f)

    def output_result(self, model):
        print(model)
        with open(os.path.join(self.project.result_path, f'{model}-result.txt')) as f:
            with open(f'./case-analysis/{model}-result.txt', 'a') as f_r:
                print(self.prj_path, file=f_r)
                print(f.read(), file=f_r)

    def clear_unused(self):
        run_command('mkdir unused', path=self.prj_path)
        run_command('mv prompt.txt vulnerable_versions.txt.bk final-patch.diff.bk target result patches ./unused/', path=self.prj_path)


    def count_vulnerable_versions(self):
        with open(f'{self.vul_version_map_path}.bk') as f:
            b = f.readlines()
        with open('./temp.txt', 'a') as f:
            print(len(b)*'a', file=f)

    def check_vulnerable_versions(self):
        with open(self.vul_version_map_path) as f:
            a = f.read()
        with open(f'{self.vul_version_map_path}.bk') as f:
            b = f.read()
        if len(a) < len(b):
            print(self.prj_path)

    def bk_vulnerable_versions(self):
        run_command(f'mv {self.vul_version_map_path}.bk {self.vul_version_map_path} ', path=self.prj_path)

    def git_apply(self):
        for commit_id, version in self.vul_commit_version_map.items():
            print(self.prj_path, commit_id, version)
            self.project.checkout(commit_id)
            run_command('git checkout .')
            result = run_command('git apply ../../final-patch.diff', path=self.npm_prj_path).stderr
            if result != '': print(result)
    
    def download_patch(self):
        response = requests.get(self.patch_url)
        with open(self.patch_path, 'wb') as f:
            f.write(response.content)
        with open(self.patch_path) as f:
            return f.read()

    def install_dependency(self):
        run_command('npm install --registry=https://registry.npmmirror.com', path=self.prj_path)

    def git_clone(self):
        self.repo_id = self.patch_url.replace('https://github.com/', '').replace(f"/commit/{self.patch_id}", '')
        self.github_url = self.patch_url.replace(f"/commit/{self.patch_id}", '')
        run_command(f"rm -rf./{self.prj_name}", path=self.npm_path)
        run_command(f"git clone {self.github_url} && mv ./{self.repo_id.split('/')[-1]} ./{self.prj_name}", path=self.npm_path)

    def extend_versions_from_tags(self):
        if 'error' in self.project.checkout('master'):
            self.project.checkout('main')
        versions = run_command('git --no-pager tag', path=self.npm_prj_path).stdout[:-1].split('\n')
        versions = list(set([i.strip('v').split('-')[0] for i in versions]))
        versions.sort()
        # commit_versions = list(self.iterate_version_commits())
        # commit_versions.sort()
        return versions

    def extend_versions_from_config(self):
        with open(self.version_map_path, 'w') as f: pass
        repo = git.Repo(self.npm_prj_path)
        versions = set()      
        for commit_hash in repo.iter_commits():
            try:
                if commit_hash.parents:
                    parent_commit = commit_hash.parents[0]
                    parent_package_json = repo.git.show(f'{parent_commit.hexsha}:package.json')
                    parent_version = json.loads(parent_package_json).get('version', None)
                else:
                    parent_version = None
                current_package_json = repo.git.show(f'{commit_hash}:package.json')
                current_version = json.loads(current_package_json).get('version', None)
            except:
                continue
            if current_version != parent_version:
                with open(self.version_map_path, 'a') as f:
                    print(commit_hash, current_version, file=f)
            if current_version is not None:
                versions.add(current_version)
        return versions
    
    def extract_vulnerable_versions(self):
        print(self.prj_path)
        with open(self.version_map_path) as f:
            lines = [i.strip() for i in f.readlines()]
        vulnerable_lines = []
        for i in lines:
            commit_id, version = i.split(' ')
            if is_commit1_earlier_than_commit2(self.patch_id, commit_id, self.npm_prj_path):
                continue
            self.project.checkout(commit_id)
            print(version)
            if self.project.jest() != 'False#0':
                continue
            vulnerable_lines.append(i)
        with open(f'{self.vul_version_map_path}', 'w') as f:
            for i in vulnerable_lines:
                print(i, file=f)

    def version_filter(self):
        version_map = {}
        with open(self.vul_version_map_path) as f:
            lines = [i.strip() for i in f.readlines()]
        for line in lines:
            commit_id, version = line.split(' ')
            if version in version_map:
                if is_commit1_earlier_than_commit2(version_map[version], commit_id, self.prj_path):
                    continue
            version_map[version] = commit_id
        with open(self.vul_version_map_path, 'w') as f:
            for version, commit_id in version_map.items():
                print(commit_id, version, file=f)

    def extract_versions(self):
        version_map = {}
        vulnerable_versions = []
        unvulnerable_versions = []
        with open(self.version_map_path) as f:
            for line in f:
                commit, version = line.strip().split(' ')
                version_map[commit] = version
        for commit in version_map.keys():
            self.project.checkout(commit)
            if self.project.jest() == 'False#0':
                vulnerable_versions.append(version_map[commit])
            else:
                unvulnerable_versions.append(version_map[commit])

    def get_transfered_cve_list(self):
        with open('/data/SCA-repair/src/unused/cve.txt') as f:
            print(self.project.cve_id)
            if self.project.cve_id in f.read() and self.project.cve_id.strip():
                cve_id = self.project.cve_id
                print(f'{cve_id} in cve.txt')
                cwe_id = get_cwe_for_cve(cve_id)
                patch_url = self.project.patch_url
                print(','.join([cve_id, cwe_id, patch_url]))
                with open('./unused/doubao.csv', 'a') as f_w:
                    print(','.join([cve_id, cwe_id, patch_url, self.prj_path]), file=f_w)

    def copy_out(self):
        with open('./unused/doubao.csv') as f:
            if self.prj_path not in f.read():
                return 
        run_command(f'cp -r {self.project.npm_prj_path} /data2/secbench-bk/')
        cp_path = os.path.join('/data2/secbench-bk/', self.project.npm_prj_path.split('/')[-1])
        run_command(f'mkdir jest-doubao', path=cp_path)
        for i in os.listdir(self.prj_path):
            if '.test.js' in i:
                run_command(f'cp {self.prj_path}/{i} {cp_path}/jest-doubao')

    def is_get_localization_oracle(self):
        import datetime
        localization_file_path = os.path.join(self.prj_path, 'localization.csv')
        month = datetime.datetime.fromtimestamp(os.path.getmtime(localization_file_path)).month
        if month != 7:
            print(f'***{self.prj_path}***')

    def compare_localization(self):
        FILE_A = os.path.join(self.prj_path, "localization.csv")
        DATA_DIR = os.path.join(self.prj_path, "localization")
        _, tool_result = main_compare_localization(FILE_A, DATA_DIR)
        output_localization_results(tool_result, './temp/localization.json', self.prj_path)
        return main_compare_localization(FILE_A, DATA_DIR)

    def get_chunk_counts(self, path):
        with open(path) as f:
            patch_content = f.read()
        current_patch = unidiff.PatchSet.from_string(patch_content)
        patches = []
        for patch in current_patch:
            patches.append(patch)
        modifications = []
        for patched_file in patches:
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
        return len(modifications)


def parse_line(line):
    parts = line.strip().split('##')
    if len(parts) != 3:
        return None, None
    unique_id = f"{parts[0]}##{parts[2]}"
    
    match = re.search(r'\[(.*?)\]', parts[1])
    if not match:
        return unique_id, set()

    content_str = match.group(1)
    if not content_str:
        return unique_id, set()
        
    try:
        content_set = set(map(int, content_str.split(',')))
        return unique_id, content_set
    except ValueError:
        return None, None


def compare_sets(set_a, set_b):
    if set_a == set_b:
        return "Equal"
    elif len(set_b) == 0:
        return "Disjoint"
    elif set_a.issubset(set_b):
        return "Subset"
    elif set_a.issuperset(set_b):
        return "Superset"
    elif not set_a.isdisjoint(set_b):
        return "Intersecting"
    else:
        return "Disjoint"

def aggregate_results(results):
    unique_results = set(results)    
    if len(unique_results) == 1:
        return unique_results.pop()
    if all(i == "Equal" for i in unique_results):
        return "Equal"
    if all(i == "Disjoint" for i in unique_results):
        return "Disjoint"
    return "Intersecting"

def main_compare_localization(file_a_path, directory_path):
    dir_data = defaultdict(dict)
    model_list = ['deepseek-api.csv', 'deepseek-api-deletedline.csv', 'deepseek-api-function.csv', 'similarity.csv', 'similarity-git.csv', 'LLM-git.csv']
    for model in model_list:
        dir_data[model] = defaultdict(set)
    for filename in os.listdir(directory_path):
        file_path = os.path.join(directory_path, filename)
        if os.path.isfile(file_path):
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    unique_id, content_set = parse_line(line)
                    if unique_id:
                        dir_data[filename][unique_id] = content_set
    all_comparison_results = defaultdict(list)
    with open(file_a_path, 'r', encoding='utf-8') as f_a:
        for i, line_a in enumerate(f_a, 1):
            parts_a = line_a.strip().split('##')
            if len(parts_a) != 3:
                print(f"error format '{line_a.strip()}'")
                continue
            unique_id_a, set_a = parse_line(line_a)
            if unique_id_a is None:
                continue
            for tool, location_item in dir_data.items():
                f = 0
                for location, set_b in location_item.items():
                    if unique_id_a == location:
                        result = compare_sets(set_a, set_b)
                        all_comparison_results[tool].append(result)
                        f = 1
                if f == 0:
                    all_comparison_results[tool].append("Disjoint")
    # for k, v in all_comparison_results.items():
    #     print(k, len(all_comparison_results[k]))
    #     print(all_comparison_results[k])
    final_result = defaultdict(str)
    for tool, results in all_comparison_results.items():
        final_result[tool] = aggregate_results(results)
    return all_comparison_results, final_result

def output_localization_results(results, file_path, prj_path):

    with open(file_path, 'r', encoding='utf-8') as file:
        data = json.load(file)
    output_result = {}
    for k, v in results.items():
        if k in ['deepseek-api.csv', 'deepseek-api-deletedline.csv', 'deepseek-api-function.csv', 'similarity.csv', 'similarity-git.csv']:
            output_result[k] = v
    
    data[prj_path] = output_result

    with open(file_path, 'w', encoding='utf-8') as file:
        json.dump(data, file, indent=4, ensure_ascii=False)
    

def get_cwe_for_cve(cve):
    API_URL = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
    API_KEY = ""
    headers = {
        "apiKey": API_KEY
    }
    response = requests.get(API_URL, headers=headers)

    cwe = []
    if response.status_code == 200:
        data = response.json()
    cwe_infos = data.get('vulnerabilities')[0].get('cve').get('weaknesses')
    for cwe_info in cwe_infos:
        cwe.append(cwe_info.get('description')[0].get('value'))
    return cwe[0]
