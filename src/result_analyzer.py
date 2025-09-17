import os
from collections import defaultdict
from collections import Counter
class ResultAnalyzer:
    def __init__(self, project):
        self.project = project
        self.result_path = project.result_path
        self.result_file_path = os.path.join(self.result_path, 'result.txt')
        self.model_list = ['codellama:latest', 'llama3.1:8b', 'deepseek-coder:6.7b', 'deepseek-coder:1.3b']

    def evaluate_model(self, model):
        true_prj_count = False
        current_true, current_all = count_result(self.result_file_path, model)
        if current_all == current_true and current_all != 0:
            true_prj_count = True
        if current_all > len(self.project.vul_commit_version_map):
            print(self.result_file_path)
        print(true_prj_count, current_true, current_all)
        return true_prj_count, current_true, current_all

    def evaluate_all(self):
        for model in self.model_list:
            true_prj_count = False
            current_true, current_all = count_result(self.result_file_path, model)
            if current_all == current_true and current_all != 0:
                true_prj_count = True
            if current_all > len(self.project.vul_commit_version_map):
                print(self.result_file_path)
            print(model, true_prj_count, current_true, current_all)
        return true_prj_count, current_true, current_all

def count_result(result_path, model):
    with open(result_path) as f:
        lines = f.readlines()
    lines = [line for line in lines if model in line or len(line.split(' ')) == 2]
    all_count = len(lines)
    true_count = len([i for i in lines if 'True' in i])
    return true_count, all_count

def count_file_accuracy(key):
    with open('./case-analysis/result.txt') as f:
        lines = [i.strip() for i in f.readlines()]
    true_count = 0
    false_count = 0
    for line in lines:
        if key in line:
            if 'True' in line:
                true_count += 1
            else: false_count += 1
    # return true_count+false_count, true_count
    # return round(true_count / (true_count+false_count), 3), true_count+false_count
    return round(true_count / (true_count+false_count), 3)

# def clear_result():
#     with open('')

def case_study(file_path):
    import ast
    true_flag = []
    false_flag = []
    with open(file_path) as f:
        lines = [ast.literal_eval(i.strip()) for i in f.readlines()]
    for line in lines:
        if line[1] == False:
            false_flag.append(line)
        else: true_flag.append(line)
    true_flag.sort(key=lambda x: x[0])
    false_flag.sort(key=lambda x: x[0])
    with open(file_path, 'w') as f:
        for i in true_flag:
            print(i, file=f)
        for i in false_flag:
            print(i, file=f)

def evaluation():
    model_list = ['deepseek-llm:7b', 'qwen2.5:7b', 'qwen2.5-coder:7b', 'deepseek-coder:6.7b',  'codellama:latest', 'llama3.1:8b', 'qwen2.5-coder:1.5b', 'deepseek-coder:1.3b', 'deepseek-api']
    model_list = ['deepseek-api']
    method_list = ['file', 'similarity', 'history']
    # method_list = ['file']
    result_list = []
    for method in method_list:
        for model in model_list:
            key = f'{model} {method}'
            result = count_file_accuracy(key)
            result_list.append((method, model, result))
    result_list.sort(key=lambda x: x[2])
    for result in result_list:
        print(result)

def get_porting_type_info():
    type_file = './patches/record.txt'
    type_dict = {}
    with open(type_file) as f:
        lines = [i.strip() for i in f.readlines()]
    for line in lines:
        pkg_name, port_type = line.split(',')
        type_dict[pkg_name] = port_type
    return type_dict

def get_result_from_status(status):
    if status in ['True', 'Check']:
        return 1
    else: return 0

def get_effectiveness_results(result_file):
    type_dict = get_porting_type_info()
    # result_file = './case-analysis/deepseek-api-result.txt'
    result_dict = defaultdict(dict)
    with open(result_file) as f:
        data = f.read()
    lines = [line for line in data.strip().split('\n') if line.strip()]
    for i in range(0, len(lines), 2):
        pkg_name = lines[i].split('/')[-1]
        status = lines[i+1].split(' ')[0]
        result_dict[pkg_name]['status'] = status
        result_dict[pkg_name]['CWE'] = lines[i].split('/')[-2]
        result_dict[pkg_name]['type'] = type_dict[pkg_name]
        result_dict[pkg_name]['result'] = get_result_from_status(status)
    return result_dict

def get_baseline_results():
    type_dict = get_porting_type_info()
    result_file = './case-analysis/baseline-result.txt'
    result_dict = defaultdict(dict)
    with open(result_file) as f:
        lines = [i.strip() for i in f.readlines()]
    for i in lines:
        pkg_path, status = i.split(' ')
        pkg_name = pkg_path.split('/')[-1]
        if status == 'CompilationError':
            continue
        result_dict[pkg_path]['status'] = status
        result_dict[pkg_name]['CWE'] = pkg_path.split('/')[-2]
        result_dict[pkg_name]['type'] = type_dict[pkg_name]
        result_dict[pkg_name]['result'] = get_result_from_status(status)
    return result_dict

def analyze_effectiveness_results():
    oralce_dict = get_effectiveness_results('./case-analysis/deepseek-api-result.txt')
    # baseline_prjs = get_baseline_prjs()
    # oralce_dict = {k: v for k, v in oralce_dict.items() if k in baseline_prjs}
    # result_dict = get_effectiveness_results('./case-analysis/deepseek-api-result.txt')
    # result_dict = get_effectiveness_results('./case-analysis/gpt4o-result.txt')
    result_dict = get_effectiveness_results('./case-analysis/qwen2.5-coder:14b-result.txt')
    # baseline_prjs = get_baseline_prjs()
    # result_dict = {k: v for k, v in result_dict.items() if k in baseline_prjs}

    # result_dict = get_baseline_results()
    print('type')
    for query_type in ['1', '2', '3', '4']:
        count1 = sum(1 for pkg_info in result_dict.values() if pkg_info.get('type') == query_type and pkg_info.get('result') == 1)
        count2 = sum(1 for pkg_info in oralce_dict.values() if pkg_info.get('type') == query_type)
        # print(f"{count1} ({count1/count2})", count2)
        print(f'& {count1} ({f'{count1/count2:.2%}'})', end=' ')
    count1 = sum(1 for pkg_info in result_dict.values() if pkg_info.get('result') == 1)
    print(f'& {count1} ({f'{count1/112:.2%}'})')
    print('\ncwe\n')
    for query_cwe in ['prototype-pollution', 'command-injection', 'code-injection', 'path-traversal', 'redos']:
        count1 = sum(1 for pkg_info in result_dict.values() if pkg_info.get('CWE') == query_cwe and pkg_info.get('result') == 1)
        count2 = sum(1 for pkg_info in oralce_dict.values() if pkg_info.get('CWE') == query_cwe)
        print(f'& {count1} ({f'{count1/count2:.2%}'})', end=' ')
        # print(f"{query_cwe}: {count1} ({count1/count2})", count2)
    count1 = sum(1 for pkg_info in result_dict.values() if pkg_info.get('result') == 1)
    print(f'& {count1} ({f'{count1/112:.2%}'})')
    count2 = sum(1 for pkg_info in result_dict.values() if pkg_info.get('status') == 'False#0')
    count3 = sum(1 for pkg_info in result_dict.values() if pkg_info.get('status') == 'False#1')
    print()
    print(count2, count3)
    print(count2/90, count3/90, count1/90)
    print(count2)


def get_duplicated_pkgs():
    data_path = '../data/jest-out-temp.txt'
    with open(data_path) as f:
        lines = [i.strip().split('/')[-1].split('_')[0] for i in f.readlines()]
    print(find_elements_over_two_occurrences(lines))

def find_elements_over_two_occurrences(input_list):
  counts = Counter(input_list)
  return [item for item, count in counts.items() if count >= 2]

def get_baseline_prjs():
    file_path = './case-analysis/baseline-result.txt'
    with open(file_path) as f:
        lines = [i.strip() for i in f.readlines()]
    prjs = []
    for i in lines:
        if 'CompilationError' in i:
            continue
        prjs.append(i.split(' ')[0].split('/')[-1])
    return prjs

def analyze_effectiveness_differences():
    dynamic_result = get_effectiveness_results('./case-analysis/deepseek-api-file-result.txt')
    compared_result = get_effectiveness_results('./case-analysis/deepseek-api-line-result.txt')
    for k, v in dynamic_result.items():
        if k not in compared_result:
            continue
        if v['status'] != compared_result[k]['status']:
            print(k)
            print(f'dynamic: {v['status']}, compare: {compared_result[k]['status']}')


def RQ3_result():
    a = [[11, 2, 99], [17, 2, 93], [20, 1, 91], [15, 7, 90], [17, 5, 90], [22, 2, 88], [17, 2, 93], [18, 2, 92], [27, 3, 82]]
    for i in a:
        for j in i:
            print(f'& {j} ({f'{j/112:.2%}'})', end=' ')
        print()

def calculate_average(file_path):
    with open(file_path) as f:
        lines = [i.strip() for i in f.readlines()]
    print(sum([int(i) for i in lines]) / len(lines))

def calculate_localization(input, base):
    input_list = [int(i) for i in input.split('&')[1:]]
    print(input_list)
    for i in input_list:
        print(f'& {i} ({f'{i/base:.2%}'})', end=' ')

if __name__ == '__main__':
    calculate_localization('& 42 & 40 & 30', 112)
    # RQ3_result()
