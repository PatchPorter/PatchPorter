import os
from common_utils import run_command, read_lines_file, parse_localization_info
from fault_localizer import FaultLocalizer, get_context, get_line_context
import json
from tree_sitter import Language, Parser
import tree_sitter_javascript

class PromptManager:
    def __init__(self, project):
        self.project = project
        self.prj_path = project.prj_path
        self.prj_name = project.prj_name
        
        self.result_path = project.result_path
        self.patch_content = project.patch_content
        self.unidiff_patch = project.unidiff_patch
        self.vul_commit_version_map = project.vul_commit_version_map
        self.target_file_path = project.target_file_path
        self.prompt_path = project.prompt_path
        self.challenge_version = self.project.get_challenge_version()

    def generate_prompt_with_localization(self, patch, target_line, target_content):
        prompt = '''You are a security vulnerability expert specializing in vulnerability analysis and repair. You excel at precisely porting security patches from one code version to another.
Core Task: Your task is to analyze a known vulnerability patch and accurately apply its core fix logic to the target vulnerable code. To help you better understand the code structure, I will provide the code context of the target code.
Input: 
- Vulnerability Patch: Source code differences (diff) containing the vulnerability fix logic.
- Target Vulnerable Code: The target vulnerable code snippet that needs to be fixed.
- Code Context: The code surrounding the target vulnerable code in the source file, provided for reference only.
Output: 
- Fixed Target Code: The repaired target vulnerable code after applying the patch logic.
Requirements: 
1. Your modifications must strictly follow the fix logic in the vulnerability patch. Do not introduce any new features, code refactoring, or formatting adjustments that are unrelated to the code change of the patch.
2. Your output should contain only the modified target vulnerable code itself. The code context is for location and understanding purposes only. It must not be modified or included in the output.
3. The final output must be pure code. Do not include any explanations or any descriptive text.

Vulnerability Patch:
```
{}
```

Target Vulnerable Code:
```
{}
```

Code Context:
```
{}
```

Output:
'''
        return prompt.format(patch, target_line, target_content)

    def generate_prompt(self, version, patch, target_content):
        prompt = '''You are an expert in the field of security vulnerabilities and are skilled at migrating vulnerability patches to other vulnerable versions of software.
Below are the task requirements:
Input: A vulnerability patch and code from another vulnerable version
Output: Code repaired according to the patch logic
Requirements:
1. Apply only the newly added code from the patch, without changing the original structure of the code.
2. Only output the code, no explanations
3. The repaired code should maintain the same syntactic structure as before the repair


Vulnerability patch:
```
{}
```
Vulnerable code:
```
{}
```
Output:
'''
        input_patch = patch
        input_code = target_content
        return prompt.format(input_patch, input_code)

    def generate_prompt_one_shot(self, version, patch, target_content):
        prompt = '''You are an expert in the field of security vulnerabilities and are skilled at migrating vulnerability patches to other vulnerable versions of software.
Below are the task requirements:
Input: A vulnerability patch and code from another vulnerable version
Output: Code repaired according to the patch logic
Requirements:
1. Apply only the newly added code from the patch, without changing the original structure of the code.
2. Only output the code, no explanations
3. The repaired code should maintain the same syntactic structure as before the repair

Here is an example:

Vulnerability patch:
```
{}
```
Vulnerable code:
```
{}
```
Output:
```
{}
```

Now, please process the following input:
Vulnerability patch:
```
{}
```
Vulnerable code:
```
{}
```
Output:
'''
        example_patch = '''function deepExtend(objects, collision, path) {
       for (name in options) {
         if (!options.hasOwnProperty(name))
           continue;
+        if (name === '__proto__')
+          continue;
 
         src = target[name];
         copy = options[name];
        '''
        example_code = '''      for (name in options) {
        if (!options.hasOwnProperty(name))
          continue;

        src = target[name];
        copy = options[name];

        // Prevent never-ending loop
        if (target === copy) {
          continue;
        '''
        example_output = '''      for (name in options) {
        if (!options.hasOwnProperty(name))
          continue;

        if (name === '__proto__')
          continue;
          
        src = target[name];
        copy = options[name];

        // Prevent never-ending loop
        if (target === copy) {
          continue;
        '''
        input_patch = patch
        input_code = target_content
        return prompt.format(example_patch, example_code, example_output, input_patch, input_code)

        instruction = "You are an expert in patch backporting. Now backport a patch to the target version. Please note that only the logic in the patch should be referenced. Ensure that the syntax structure of the output code remains consistent with the input code, otherwise it may lead to syntax errors.\n"
        instruction_patch = f"Here is the patch:\n\n```\n{patch}\n```\n\n"
        instruction_file = f'Here is the code of the target file:\n\n```\n{target_content}\n```\n\n'
        instruction_output = 'Here is the output of the target file:'
        example = """Here is an example.
Here is the patch: 
@@ -44,6 +44,8 @@ function deepExtend(objects, collision, path) {
       for (name in options) {
         if (!options.hasOwnProperty(name))
           continue;
+        if (name === '__proto__')
+          continue;
 
         src = target[name];
         copy = options[name];

Here is the code of the target file: 
      for (name in options) {
        if (!options.hasOwnProperty(name))
          continue;

        src = target[name];
        copy = options[name];

        // Prevent never-ending loop
        if (target === copy) {
          continue;

please only output the content of the file and do not use "javascript ``````":
      for (name in options) {
        if (!options.hasOwnProperty(name))
          continue;

        src = target[name];
        copy = options[name];

        // Prevent never-ending loop
        if (target === copy) {
          continue;
"""
        return instruction + example + instruction_patch + instruction_file + instruction_output

    def get_target_file_basic(self):
        target_file = self.project.get_target_file_content()
        if target_file is None:
            return None
        target_file_content, target_file_length = target_file
        if target_file_length > 500:
            return None
        return target_file_content

    def store_prompt_LLM_line_fault_localization(self):
        for file_name in os.listdir(self.project.localization_info_path):
            print(file_name)
            model_name = file_name.split('.csv')[0]
            localization_path = os.path.join(self.project.localization_info_path, file_name)
            commit_linos = parse_localization_info(localization_path)
            target_linos = None
            for commit_id, linos in commit_linos.items():
                version = self.project.find_version_from_commit(commit_id)
                if version == self.challenge_version:
                    target_linos = linos
                    target_commit_id = commit_id
            if target_linos is None:
                continue
            linos = process_overlapped_linos(target_linos)
            commit_id = target_commit_id
            version = self.challenge_version
            output_path = os.path.join(self.prompt_path, f'{version}@{model_name}@tracking.json')
            if os.path.exists(output_path):
                continue 
            target_file_lines = self.project.get_target_file_content_commit(commit_id)
            prompts = []
            hunks = self.project.split_hunks_into_continuous_changes()
            output_lines = []
            for i, lines in linos.items():
                if lines[0] == -1:
                    target_file_content = target_file_lines[-1]
                else:
                    lines.sort()
                    target_file_content = ''.join(target_file_lines[lines[0]-1:lines[-1]])
                target_hunks = '\n'.join([str(hunks[int(j)]) for j in i.split('@')])
                print(target_hunks)
                prompts.append(self.generate_prompt_one_shot(version, target_hunks, target_file_content))
                output_lines.append(lines)
            output_obj = {'prj_path': self.prj_path, 'version': version, 'commit_id': commit_id, 'prompt': prompts, 'context_lines': output_lines}
            with open(output_path, 'w') as f:
                json.dump(output_obj, f, indent=4)


    def get_file_content(self):
        target_file_content = self.project.get_target_file_content_commit(self.project.get_challenge_commit())
        return target_file_content

    def get_reduced_function_content(self, hunk_id):
        oracle_file = './case-analysis/baseline_ppathf_reduced.json'
        with open(oracle_file, 'r') as f:
            data = json.load(f)
        for i in data:
            id = i['id']
            pkg_name = id.split('#')[0]
            index = id.split('#')[1][len('mystique-')]
            if index == hunk_id and self.prj_path.split('/')[-1] == pkg_name:
                return i['func_before_sliced_target']
        return self.get_file_content()
        

    def get_function_content(self, hunk_id):
        oracle_file = './case-analysis/baseline_ppathf_reduced.json'
        with open(oracle_file, 'r') as f:
            data = json.load(f)
        for i in data:
            id = i['id']
            pkg_name = id.split('#')[0]
            index = id.split('#')[1][len('mystique-')]
            if index == hunk_id and self.prj_path.split('/')[-1] == pkg_name:
                return i['func_before_target']
        return self.get_file_content()


    def store_prompt_LLM_with_location(self, model):
        for file_name in os.listdir(self.project.localization_info_path):
            model_name = file_name.split('.csv')[0]
            if model != model_name:
                continue
            localization_path = os.path.join(self.project.localization_info_path, file_name)
        ### follow the oracle localization
        for i in range(1):
            localization_path = os.path.join(self.prj_path, f'localization.csv')
            model_name = model
            commit_linos = parse_localization_info(localization_path)

            target_linos = None
            for commit_id, linos in commit_linos.items():
                version = self.project.find_version_from_commit(commit_id)
                if version == self.challenge_version:
                    target_linos = linos
                    target_commit_id = commit_id
            if target_linos is None:
                continue

            commit_id = target_commit_id
            version = self.challenge_version
            output_path = os.path.join(self.prompt_path, f'{version}@{model_name}@tracking.json')

            target_file_content = self.project.get_target_file_content_commit_all(commit_id)
            target_file_lines = self.project.get_target_file_content_commit(commit_id)

            prompts = []
            before_prompts = []

            hunks = self.project.get_continuous_hunk_content()
            depenent_hunk_info = self.analyze_dependency_hunk()
            # print(depenent_hunk_info)
            # for i, lines in list(linos.items())[::-1]:
            #     result = depenent_hunk_info[int(i)][-1]
            #     with open('./temp.txt', 'a') as f:
            #         print(result, file=f)

            for i, lines in list(linos.items())[::-1]:
                target_hunks = '\n'.join([str(hunks[int(j)]) for j in i.split('@')])
                if len(lines) == 0 or lines[0] == -1:
                    target_file_content = target_file_lines[-1]
                    before_prompts.append([[target_hunks], '', [-1], ''])
                else:
                    lines.sort()
                    target_lines = get_line_context(target_file_content, lines)
                    if target_file_content.strip() == '':
                        continue
                    if model == 'deepseek-api-file':
                        depenent_hunk_info[int(i)][-1] = -1
                    if model == 'deepseek-api-function':
                        depenent_hunk_info[int(i)][-1] = -2
                    if model == 'deepseek-api-reducedfunction':
                        depenent_hunk_info[int(i)][-1] = -3
                    if model == 'deepseek-api-line':
                        depenent_hunk_info[int(i)][-1] = 1

                    if depenent_hunk_info[int(i)][-1] == 0:
                        # target_contexts = get_context(target_file_content, lines)
                        # target_contexts = self.merge_target_context(target_contexts)
                        # before_prompts.append([[target_hunks], target_contexts, lines, target_lines])
                        target_contexts = self.get_file_content()
                        before_prompts.append([[target_hunks], target_contexts, lines, target_lines])
                    elif depenent_hunk_info[int(i)][-1] > 0:
                        target_contexts = get_line_context(target_file_content, lines)
                        before_prompts.append([[target_hunks], target_contexts, lines, target_lines])
                    elif depenent_hunk_info[int(i)][-1] == -1:
                        target_contexts = self.get_file_content()
                        before_prompts.append([[target_hunks], target_contexts, lines, target_lines])
                    elif depenent_hunk_info[int(i)][-1] == -2:
                        target_contexts = self.get_function_content(i)
                        before_prompts.append([[target_hunks], target_contexts, lines, target_lines])
                    elif depenent_hunk_info[int(i)][-1] == -3:
                        target_contexts = self.get_reduced_function_content(i)
                        before_prompts.append([[target_hunks], target_contexts, lines, target_lines])
            for before_prompt in before_prompts:
                vulnerable_code = before_prompt[3]
                # print(f"****{before_prompt[0]}****")
                if all(i.startswith('+') and '\n-' not in i for i in before_prompt[0]):
                    vulnerable_code = '<add here>\n' + vulnerable_code
                prompt = self.generate_prompt_with_localization(f"\n```\n```\n".join(before_prompt[0]), vulnerable_code, ''.join(before_prompt[1]))
                prompts.append({'prompt': prompt, 'context': before_prompt[3], 'line': before_prompt[2]})
            output_obj = {'prj_path': self.prj_path, 'version': version, 'commit_id': commit_id, 'prompt': prompts}
            with open(output_path, 'w') as f:
                json.dump(output_obj, f, indent=4)

    def merge_target_context(self, target_contexts):
        merged_contexts = []
        for line, target_context in target_contexts.items():
            if not is_element_in_list_element(target_context, merged_contexts):
                merged_contexts.append(target_context)
        return '\n'.join(merged_contexts)

    def store_prompt_LLM_function_line_fault_localization(self, model):
        # run_command('rm -rf ./prompt/*', path=self.prj_path)
        for file_name in os.listdir(self.project.localization_info_path):
            model_name = file_name.split('.csv')[0]
            if model not in model_name:
                continue
            localization_path = os.path.join(self.project.localization_info_path, file_name)
            commit_linos = parse_localization_info(localization_path)
            # print(commit_linos)
            target_linos = None
            for commit_id, linos in commit_linos.items():
                version = self.project.find_version_from_commit(commit_id)
                if version == self.challenge_version:
                    target_linos = linos
                    target_commit_id = commit_id
            if target_linos is None:
                continue
            # linos = process_overlapped_linos(target_linos)
            commit_id = target_commit_id
            version = self.challenge_version
            output_path = os.path.join(self.prompt_path, f'{version}@{model_name}@tracking.json')
            # if os.path.exists(output_path):
            #     continue
            target_file_content = self.project.get_target_file_content_commit_all(commit_id)
            target_file_lines = self.project.get_target_file_content_commit(commit_id)
            prompts = []
            before_prompts = []
            # hunks = self.project.split_hunks_into_continuous_changes()
            hunks = self.project.get_continuous_hunk_content()
            depenent_hunk_info = self.analyze_dependency_hunk()
            # for i, lines in linos.items():
            # print(depenent_hunk_info)
            # print(linos)
            for i, lines in list(linos.items())[::-1]:
                target_hunks = '\n'.join([str(hunks[int(j)]) for j in i.split('@')])
                if len(lines) == 0 or lines[0] == -1:
                    target_file_content = target_file_lines[-1]
                    before_prompts.append([[target_hunks], '', [-1]])
                else:
                    lines.sort()
                    if target_file_content.strip() == '':
                        continue
                    if depenent_hunk_info[int(i)][-1] == 0:
                        target_contexts = get_context(target_file_content, lines)
                        for line, target_context in target_contexts.items():
                            before_prompts.append([[target_hunks], target_context, [line]])
                    else:
                        target_contexts = get_line_context(target_file_content, lines)
                        before_prompts.append([[target_hunks], target_contexts, lines])

            # for i in before_prompts:
            #     print(i)
            before_prompts = merge_prompts(before_prompts)
            for before_prompt in before_prompts:
                vulnerable_code = before_prompt[1]
                # print(f"****{before_prompt[0]}****")
                if all(i.startswith('+') and '\n-' not in i for i in before_prompt[0]):
                    vulnerable_code = '<add here>\n' + vulnerable_code
                prompt = self.generate_prompt(version, f"\n```\n```\n".join(before_prompt[0]), vulnerable_code)
                prompts.append({'prompt': prompt, 'context': before_prompt[1], 'line': before_prompt[2]})
            output_obj = {'prj_path': self.prj_path, 'version': version, 'commit_id': commit_id, 'prompt': prompts}
            with open(output_path, 'w') as f:
                json.dump(output_obj, f, indent=4)

    def store_prompt_line_fault_localization(self):
        commit_linos = parse_localization_info(self.project.localization_info_path)
        for commit_id, linos in commit_linos.items():
            version = self.project.find_version_from_commit(commit_id)
            if version == self.challenge_version:
                target_linos = linos
                target_commit_id = commit_id
        linos = process_overlapped_linos(target_linos)
        commit_id = target_commit_id
        version = self.challenge_version
        output_path = os.path.join(self.prompt_path, f'{version}@gitlog.json')
        # if os.path.exists(output_path):
        #     return 
        target_file_lines = self.project.get_target_file_content_commit(commit_id)
        prompts = []
        hunks = self.project.get_hunks()
        output_lines = []
        for i, lines in linos.items():
            target_hunks = '\n'.join([str(hunks[int(j)]) for j in i.split('@')])
            target_file_content = ''.join(target_file_lines[lines[0]-1:lines[-1]])
            prompts.append(self.generate_prompt(version, target_hunks, target_file_content))
            output_lines.append(lines)
        output_obj = {'prj_path': self.prj_path, 'version': version, 'commit_id': commit_id, 'prompt': prompts, 'context_lines': output_lines}
        with open(output_path, 'w') as f:
            json.dump(output_obj, f, indent=4)

    def store_prompt_fault_localization(self):
        for commit_id, version in self.vul_commit_version_map.items():
            if version != self.challenge_version:
                continue
            self.project.checkout(commit_id)
            output_path = os.path.join(self.prompt_path, f'{version}@similarity.json')
            if os.path.exists(output_path):
                continue
            if not os.path.exists(self.target_file_path):
                continue
            fault_localizer = FaultLocalizer(self.project)
            context_lines = fault_localizer.localization_context()
            hunks = fault_localizer.hunks
            target_file_lines = read_lines_file(self.target_file_path)
            prompts = []
            for i in range(len(context_lines)):
                if len(context_lines[i]) == 0:
                    context_lines[i] = [1, len(target_file_lines)]
                target_file_content = ''.join(target_file_lines[context_lines[i][0]-1:context_lines[i][-1]])
                prompts.append(self.generate_prompt(version, hunks[i], target_file_content))
            output_obj = {'prj_path': self.prj_path, 'version': version, 'commit_id': commit_id, 'prompt': prompts, 'context_lines': context_lines}

            with open(output_path, 'w') as f:
                json.dump(output_obj, f, indent=4)

    def store_prompt_whole_file(self):
        for commit_id, version in self.vul_commit_version_map.items():
            if version != self.challenge_version:
                continue
            output_path = os.path.join(self.prompt_path, f'{version}@file.json')
            # if os.path.exists(output_path):
            #     continue
            target_file_content = self.project.get_target_file_content_commit(commit_id)
            target_file_content = ''.join(target_file_content)
            if target_file_content is None:
                continue
            prompt = [self.generate_prompt(version, self.patch_content, target_file_content)]
            output_obj = {'prj_path': self.prj_path, 'version': version, 'commit_id': commit_id, 'prompt': prompt}
            with open(output_path, 'w') as f:
                json.dump(output_obj, f, indent=4)
        self.project.chmod_prompt_path()

    def analyze_dependency_hunk(self):
        white_list = ['Error', 'Object', 'Array', 'isNaN', 'parseInt', 'require', 'console', 'TypeError', 'JSON']
        chunks = get_continuous_hunks(self.unidiff_patch)
        pre_commit_file_content = run_command(f'git show {self.project.patch_id}^:{self.unidiff_patch[0].path}', path=self.project.npm_prj_path).stdout
        post_commit_file_content = run_command(f'git show {self.project.patch_id}:{self.unidiff_patch[0].path}', path=self.project.npm_prj_path).stdout
        result = []
        for chunk in chunks:
            dependent = 2
            pre_chunk_linos, post_chunk_linos = chunk
            pre_def_use = get_def_use(pre_chunk_linos, pre_commit_file_content)
            post_def_use = get_def_use(post_chunk_linos, post_commit_file_content)
            for i in post_def_use['use']:
                if i not in post_def_use['def'] and i not in white_list and i not in pre_def_use['use'] and i not in pre_def_use['def']:
                    dependent = 0
                    break
            result.append([pre_def_use, post_def_use, dependent])
        for def_use in result:
            pre_def_use = def_use[0]
            post_def_use = def_use[1]
            if def_use[-1] == 0:
                dependent = 1
                for i in post_def_use['use']:
                    if i not in post_def_use['def'] and i not in white_list and i not in pre_def_use['use'] and i not in pre_def_use['def']:
                        if not any(i in j[0]['use'] or i in j[1]['def'] or i in j[0]['def'] for j in result):
                            dependent = 0
                            break
                def_use[-1] = dependent
        return result

def get_def_use(chunk, file_content):
    result = {"def": [], "use": []}
    if len(chunk) == 0:
        return result
    JS_LANGUAGE = Language(tree_sitter_javascript.language())
    parser = Parser(JS_LANGUAGE)
    tree = parser.parse(file_content.encode('utf-8'))
    root_node = tree.root_node

    line_start = chunk[0]
    line_end = chunk[-1]

    def traverse(node):
        if node.type in ['variable_declarator', 'lexical_declaration', 'variable_declaration', 'arrow_function']:
            for child in node.children:
                if child.type == 'identifier' and child.start_point[0]+1 >= line_start and child.end_point[0]+1 <= line_end:
                    var_name = child.text.decode('utf8')
                    if var_name not in result["def"]:
                        result["def"].append(var_name)
        elif node.type == 'function_declaration':
            name_node = node.child_by_field_name('name')
            if name_node and name_node.start_point[0]+1 >= line_start and name_node.end_point[0]+1 <= line_end:
                func_name = name_node.text.decode('utf8')
                if func_name not in result["def"]:
                    result["def"].append(func_name)
        if node.start_point[0]+1 >= line_start and node.end_point[0]+1 <= line_end:
            if node.type in ['variable_declarator', 'lexical_declaration', 'variable_declaration']:
                for child in node.children:
                    if child.type == 'identifier':
                        var_name = child.text.decode('utf8')
                        if var_name not in result["def"]:
                            result["def"].append(var_name)
            elif node.type in ['for_in_statement', 'for_of_statement']:
                left_node = node.child_by_field_name('left')
                if left_node:
                    if left_node.type == 'identifier':
                        var_name = left_node.text.decode('utf8')
                        if var_name not in result["def"]:
                            result["def"].append(var_name)
                    elif left_node.type in ['variable_declaration', 'lexical_declaration']:
                        declarator = left_node.child_by_field_name('declarations').named_children[0]
                        if declarator and declarator.type == 'variable_declarator':
                            name_node = declarator.child_by_field_name('name')
                            if name_node and name_node.type == 'identifier':
                                var_name = name_node.text.decode('utf8')
                                if var_name not in result["def"]:
                                    result["def"].append(var_name)
                right_node = node.child_by_field_name('right')
                if right_node and right_node.type == 'identifier':
                    var_name = right_node.text.decode('utf8')
                    if var_name not in result["def"] and var_name not in result["use"]:
                        result["use"].append(var_name)
            elif node.type == 'function_declaration':
                name_node = node.child_by_field_name('name')
                if name_node:
                    func_name = name_node.text.decode('utf8')
                    if func_name not in result["def"]:
                        result["def"].append(func_name)
            elif node.type == 'formal_parameters':
                for child in node.children:
                    if child.type == 'identifier':
                        param_name = child.text.decode('utf8')
                        if param_name not in result["def"]:
                            result["def"].append(param_name)
                    elif child.type == 'rest_pattern':
                        for c in child.children:
                            if c.type == 'identifier':
                                param_name = c.text.decode('utf8')
                                if param_name not in result["def"]:
                                    result["def"].append(param_name)
            elif node.type == 'identifier':
                parent = node.parent
                if parent and parent.type not in ['member_expression', 'property_identifier']:
                    var_name = node.text.decode('utf8')
                    if var_name not in result["use"]:
                        result["use"].append(var_name)
            elif node.type == 'member_expression':
                object_node = node.child_by_field_name('object')
                if object_node and object_node.type == 'identifier':
                    var_name = object_node.text.decode('utf8')
                    if var_name not in result["def"] and var_name not in result["use"]:
                        result["use"].append(var_name)
        for child in node.children:
            traverse(child)
    
    traverse(root_node)
    return result


def get_continuous_hunks(patch):
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
                    current_delete.append(line.source_line_no)
                elif line.is_added:
                    current_add.append(line.target_line_no)
                else:
                    if current_delete or current_add:
                        modifications.append((current_delete, current_add))
                    current_delete = []
                    current_add = []
            if current_delete or current_add:
                modifications.append((current_delete, current_add))
                current_delete = []
                current_add = []
    return modifications

def process_overlapped_linos(data):
    merged_groups = [{frozenset([key]): set(values)} for key, values in data.items()]
    changed = True
    while changed:
        changed = False
        new_groups = []
        while merged_groups:
            current = merged_groups.pop(0)
            current_keys, current_values = list(current.items())[0]
            merged = False
            for group in new_groups:
                group_keys, group_values = list(group.items())[0]
                if current_values & group_values:
                # if current_values & group_values and -1 not in current_values:
                    new_key = group_keys | current_keys
                    new_values = group_values | current_values
                    new_groups.remove(group)
                    new_groups.append({new_key: new_values})
                    merged = True
                    changed = True
                    break
            if not merged:
                new_groups.append(current)
        merged_groups = new_groups
    final_result = {}
    for group in merged_groups:
        group_keys, group_values = list(group.items())[0]
        final_key = "@".join(sorted(group_keys, key=int))
        final_result[final_key] = list(group_values)
    return final_result


def is_element_in_list_element(element, target_list):
    for item in target_list:
        if element in item:
            return True
    return False

def merge_prompts(prompts):
    prompts.sort(key=lambda x: len(x[1]), reverse=True)
    before_prompts = []
    print(prompts)
    for prompt in prompts:
        if len(prompt) == 4:
            context_index = 3
        else: context_index = 1
        flag = 0
        target_context = prompt[context_index]
        target_hunks = prompt[0][0]
        for before_prompt in before_prompts:
            current_target_hunks_list = before_prompt[0]
            current_context = before_prompt[context_index]
            if target_context in current_context and target_context != '':
                print(f'{'*'*100}')

                if target_hunks not in current_target_hunks_list:
                    current_target_hunks_list.append(target_hunks)
                flag = 1
            elif current_context in target_context and current_context != '':
                before_prompt[context_index] = target_context
                if target_hunks not in current_target_hunks_list:
                    current_target_hunks_list.append(target_hunks)
                flag = 1
        if flag == 0:
            before_prompts.append(prompt)
    return before_prompts
