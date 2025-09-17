from common_utils import run_command, remove_duplicate_lines, checkout_commit, is_commit1_earlier_than_commit2, get_linos
import os
import json
import logging

# model_list = ['llama3.1:8b', 'codellama:latest', 'deepseek-coder:6.7b', 'deepseek-coder:1.3b']
# model_list = ['deepseek-coder:1.3b']
model_list = ['deepseek-llm:7b', 'qwen2.5:7b', 'qwen2.5-coder:7b', 'deepseek-coder:6.7b',  'codellama:latest', 'llama3.1:8b', 'qwen2.5-coder:1.5b', 'deepseek-coder:1.3b', 'deepseek-api']
model_list = ['deepseek-api']
target_path = '../temp-backport-output'

class TestManager:
    # True success
    # False#0 backport failed
    # False#1 syntax error
    # False#2 not defined
    # False#3 fault localization error
    # False#4 file too long

    def __init__(self, project):
        self.project = project

        self.prj_path = project.prj_path
        self.prj_name = project.prj_name
        self.result_path = project.result_path
        self.prompt_path = project.prompt_path
        self.target_file_name = project.target_file_name
        self.target_file_path = project.target_file_path
        self.patch_path = project.final_patch_path
        self.result_file = os.path.join(self.prj_path, 'result.txt')
        # self.name_history = self.project.get_target_name_history()
        self.npm_prj_path = self.project.npm_prj_path

    def output_backport_file(self):
        for file_name in os.listdir(self.prompt_path):
            if 'json' not in file_name:
                continue
            file_path = os.path.join(self.prompt_path, file_name)
            version = file_name[:file_name.find('-')]
            commit_id = self.project.find_commit_from_version(version)
            self.project.checkout(commit_id)
            if self.localization_checker(version) == False or self.length_checker(version) == False:
                continue
            prj_version_path = os.path.join(target_path, f'{self.prj_name}-{version}')
            # run_command(f'mkdir {self.prj_name}-{version}', path=target_path)
            # print(f"cp {self.target_file_path} {prj_version_path}/{self.target_file_name}'")
            # run_command(f'cp {self.target_file_path} {prj_version_path}/{self.target_file_name}')
            # self.backport_src(file_path)
            # run_command(f'cp {self.target_file_path} {prj_version_path}/change_{self.target_file_name}')
            # run_command(f'cp {self.patch_path} {prj_version_path}')
            # run_command(f'cp {file_path} {prj_version_path}')
            with open(file_path) as f:
                json_content = json.load(f)
            input = json_content['prompt'][0]
            input = input[input.rfind('Here is the patch:'):]
            flag = 0
            for k, v in json_content.items():
                if 'output' in k:
                    input += f'\n\n{k}:\n{v[0]}'
                    flag = 1
            if flag == 0:
                continue
            with open(os.path.join(target_path, self.prj_name+file_name.replace('json', 'txt')), 'w') as f:
                f.write(input)

    def clear_result_file(self):
        with open(self.result_file) as f:
            history_count = f.read().count('history') / 2
        count = 0
        output = []
        with open(self.result_file) as f:
            lines = [i.strip() for i in f.readlines()]
            for line in lines:
                if 'history' in line:
                    if count >= history_count:
                        output.append(line)
                    else: count += 1
                else: output.append(line)
        with open(self.result_file, 'w') as f:
            for line in output:
                print(line, file=f)


    def get_baseline_result(self, baseline_file_path):
        with open(baseline_file_path) as f:
            json_content = json.load(f)
        id = self.prj_path.split('/')[-1]
        for k, v in json_content.items():
            if id in k:
                return v['target_before'], v['target_after']
        return None

    def baseline_replace(self, target_code, target_after, target_file_path):
        with open(target_file_path) as f:
            content = f.read()
        content = content.replace(target_code, target_after)
        with open(target_file_path, 'w') as f:
            f.write(content)

    def output_baseline_result(self, baseline, baseline_file_path):
        # result_file = os.path.join(self.result_path, f'{baseline}-result.txt')
        result_file = f'./case-analysis/{baseline}-result.txt'
        code = self.get_baseline_result(baseline_file_path)
        if code is None or code[0] is None:
            result = 'CompilationError'
        else:
            target_code, target_after = code
            if '```' in target_after:
                target_after = target_after[:target_after.find('```')]
            commit_id = self.project.get_challenge_commit()
            target_file_path = os.path.join(self.project.npm_prj_path, self.project.get_responding_file_name(commit_id))
            self.project.checkout(commit_id)
            self.baseline_replace(target_code, target_after, target_file_path)
            result = self.project.jest()
            output_file_path = os.path.join(self.prj_path, 'output-result' ,f'{baseline}-result.js')
            run_command(f'cp {target_file_path} {output_file_path}', path=self.prj_path)
            self.project.checkout('.')
        with open(result_file, 'a') as f:
            print(self.prj_path, result, file=f)

    def output_backport_result(self, model):
        # run_command('rm -rf ./output-result/*', path=self.prj_path)
        challenge_version = self.project.get_challenge_version()
        run_command('mkdir result', path=self.prj_path)
        result_file_path = os.path.join(self.result_path, f'{model}-result.txt')
        run_command('mkdir output-result', path=self.prj_path)
        for file_name in os.listdir(self.prompt_path):
            # if model not in file_name:
                # continue
            if model != file_name.split('@')[1]:
                continue
            if 'json' not in file_name or not file_name.startswith(challenge_version):
                continue
            if 'tracking' in file_name:
                split_list = file_name.split('@')
                localization_method = f'{split_list[1]}@{split_list[2]}'
            elif 'gitlog' in file_name: localization_method = 'gitlog'
            elif 'similarity' in file_name: localization_method = 'similarity'
            elif 'file' in file_name: localization_method = 'file'
            file_path = os.path.join(self.prompt_path, file_name)
            with open(file_path) as f:
                json_content = json.load(f)
            version = json_content['version']
            # run_command('npm install --registry=https://registry.npmmirror.com', path=self.project.npm_prj_path)
            commit_id = self.project.find_commit_from_version(version)
            target_file_path = os.path.join(self.project.npm_prj_path, self.project.get_responding_file_name(commit_id))
            # model_list = ['deepseek-api', 'qwen2.5-coder:14b', 'codellama:13b', 'starcoder2:instruct', 'qwen2.5:14b']
            # for model in model_list:
            self.project.checkout(commit_id)
            if self.replace_src(file_path, target_file_path, model) is None:
                continue
            with open(target_file_path) as f:
                content = f.read()
            result = self.project.jest()
            print(result)
            output_file_path = os.path.join(self.prj_path, 'output-result' ,f'{version}-{model}-{localization_method}-result.js')
            run_command(f'cp {target_file_path} {output_file_path}', path=self.prj_path)
            with open(result_file_path, 'w') as f:
                print(result, version, model, localization_method, file=f)
            self.project.checkout('.')
        # remove_duplicate_lines(self.result_file)
        
    # def get_responding_file_name(self, commit_id):
    #     for i in self.name_history:
    #         if is_commit1_earlier_than_commit2(i[0], commit_id, path=self.npm_prj_path):
    #             return i[1]

    def replace_src(self, file_path, target_file_path, model):
        with open(file_path) as f:
            json_content = json.load(f)
        if f'{model}-output' not in json_content:
            return None
        input = [int(i['line'][0]) for i in json_content['prompt']]
        indexed_list = [(value, index) for index, value in enumerate(input)]
        indexed_list.sort(key=lambda x: x[0], reverse=True)
        sorted_indices = [index for value, index in indexed_list]
        for i in sorted_indices:
            output = json_content[f'{model}-output'][i]
        # for i, output in enumerate(json_content[f'{model}-output']):
            lino = int(json_content['prompt'][i]['line'][0])
            with open(target_file_path, "r") as file:
                target_file = file.read()
            output_content = filter_LLM_output(output)
            context = json_content['prompt'][i]['context']
            # print(context, output_content, output)
            if target_file.count(context) == 1:
                # print(output_content)
                target_file = target_file.replace(context, output_content)
                # print(f"{"*"*100}\n{target_file}\n{"*"*100}\n")
            else:
                target_file = replace_nearest(target_file, lino, context, output_content)
                with open('./error-log/multireplace.log', 'a') as f:
                    print(self.prj_path, i, file=f)
            with open(target_file_path, 'w') as f:
                f.write(target_file)
        return 0
    
    def backport_src(self, file_path, target_file_path, model):
        with open(file_path) as f:
            json_content = json.load(f)
        with open(target_file_path, "r") as file:
            lines = file.readlines()
        for i, output in enumerate(json_content[f'{model}-output']):
            output_content = filter_LLM_output(output)
            if 'context_lines' not in json_content:
                replace_file(target_file_path, output_content)
            else:
                context_line = json_content['context_lines'][i]
                lines = replace_lines_in_file(lines, context_line[0], context_line[-1], output_content)
        if 'context_lines' in json_content:
            with open(target_file_path, 'w') as f:
                for line in lines:
                    print(line, end='', file=f)

    def output_backport_result_old(self):
        if not os.path.exists(self.result_path):
            run_command('mkdir result', path=self.prj_path)
        self.result_file = os.path.join(self.result_path, 'result.txt')
        with open(self.result_file, 'w') as f: ...
        for file_name in os.listdir(self.result_path):
            for model_name in [i for i in model_list if i in file_name]:
                file_path = os.path.join(self.result_path, file_name)
                version = file_name.split(f'-{model_name}')[0]
                commit_id = self.project.project_utils.find_commit_from_version(version)
                target_file_path = self.get_responding_file_name(commit_id)
                self.project.checkout(commit_id)
                if self.localization_checker(version) == False or self.length_checker(version) == False:
                    continue
                self.backport_src_whole_file(file_path, target_file_path)
                result = self.project.jest()
                with open(self.result_file, 'a') as f:
                    print(result, version, model_name, file=f)
        remove_duplicate_lines(self.result_file)

    def backport_src_whole_file(self, file_path, target_file_path):
        with open(file_path) as f:
            backport_content = filter_LLM_output(f.read())
        with open(target_file_path, 'w') as f:
            f.write(backport_content)

    def localization_checker(self, version):
        if not os.path.exists(self.target_file_path):
            with open(self.result_file, 'a') as f:
                print('False#3', version, file=f)
            return False
        return True

    def length_checker(self, version):
        _, target_file_length = self.project.get_target_file_content()
        if target_file_length > 500:
            with open(self.result_file, 'a') as f:
                print('False#4', version, file=f)
            return False
        return True

    def is_exist_test_file(self):
        search_path = os.path.join(self.prj_path, 'node_modules', self.prj_name)
        items = []
        for root, dirs, files in os.walk(search_path):
            for name in files:
                if 'test' in name:
                    items.append(os.path.join(root, name))
            for name in dirs:
                if 'test' in name:
                    items.append(os.path.join(root, name))
        if len(items) == 0:
            print(search_path, items[:5])
        return items

def filter_LLM_output(content):
    left_index = content.find('```')
    if left_index == -1: return content
    if content[left_index: left_index+len('```javascript')] == '```javascript': left_index = left_index+len('```javascript')
    else: left_index = left_index + len('```')
    content = content[left_index:]
    right_index = content.rfind('```')
    if right_index == -1:
        return content
    return content[: right_index].strip('\n')

def replace_lines_in_file(lines, n, m, new_content):
    if n == -1:
        n = len(lines)
        m = n
    n_index = n - 1
    m_index = m
    if not new_content.endswith('\n'):
        new_content += '\n'
    lines[n_index] = new_content
    for i in range(n, m):
        lines[i] = ''
    return lines
    # with open(file_path, "w") as file:
    #     file.writelines(lines)

def replace_file(file_path, new_content):
    with open(file_path, "w") as file:
        file.write(new_content)


def replace_nearest(content, lino, code_snippet, target_code_snippet):
    indices = find_all_code_snippet_indices(content, code_snippet)
    lineno = [abs(lino-content[:i].count('\n')-1) for i in indices]
    min_index = min(range(len(lineno)), key=lineno.__getitem__)
    content = content[:indices[min_index]] + target_code_snippet + content[indices[min_index]+len(code_snippet):]
    return content

def find_all_code_snippet_indices(content, code_snippet):
    indices = []
    index = -1
    while True:
        index = content.find(code_snippet, index + 1)
        if index == -1:
            break
        indices.append(index)
    return indices

if __name__ == '__main__':
    file_path = '/data/SCA-repair/SecBench.js/redos/tough-cookie_2.3.2/node_modules/tough-cookie/lib/cookie.js'
