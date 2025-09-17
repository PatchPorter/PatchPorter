from concurrent.futures import ProcessPoolExecutor
from project import Project
import os
from result_analyzer import ResultAnalyzer
from fault_localizer import FaultLocalizer
from prompt_manager import PromptManager
from meta_manager import MetaManager
from test_manager import TestManager
from result_analyzer import evaluation, case_study
from untangler import untangler
from LLM_handler import LLMHandler
from common_utils import run_command
from collections import OrderedDict, defaultdict, Counter

import logging
logging.basicConfig(
    level=logging.ERROR,
    format='%(asctime)s %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S', 
)


def get_fixed_project_paths():
    with open('../data/jest-out-temp.txt', 'r') as f:
        return [os.path.abspath(i) for i in f.read().splitlines()]

def single_process(handler, task, path=None, *args, **kwargs):
    print(task, 'starting')
    f = False
    if path is None:
        target_prjs = get_fixed_project_paths()
        results = []
        for prj_path in target_prjs:
            # if prj_path == '/data/SCA-repair/SecBench.js/redos/method-override_2.0.0':
            #     f = True
            #     continue
            # if f is False:
            #     continue
            print(prj_path)
            prj_object = Project(prj_path)
            task_object = handler(prj_object)
            
            result = getattr(task_object, task)(*args, **kwargs)
            # try:
            #     result = getattr(task_object, task)(*args, **kwargs)
            # except Exception as e:
            #     with open('./error-log/record.log', 'a') as f:
            #         print(f'{prj_path} {task} wrong: {e}', file=f)

        #     results.append(result)
        #     print(result)
        # analyze_localzation_results(results)
    else:
        prj_object = Project(path)
        handler = handler(prj_object)
        return getattr(handler, task)(*args, **kwargs)

def multi_process(handler, task, path=None, *args, **kwargs):
    print(task, 'starting')
    target_prjs = get_fixed_project_paths()
    prj_objects = [Project(prj_path) for prj_path in target_prjs]
    task_objects = [handler(prj_object) for prj_object in prj_objects]
    tasks = [getattr(task_object, task) for task_object in task_objects]
    with ProcessPoolExecutor(max_workers=16) as executor:
        futures = [executor.submit(task, *args, **kwargs) for task in tasks]

def whole_process(path=None):
    if path is None:
        process = multi_process
    else: process = single_process
    process = single_process
    for model in ['deepseek-api-function', 'deepseek-api-line', 'deepseek-api-file']:
    # for model in ['deepseek-api-structure']:
    # model = 'qwen2.5-coder:14b'
    # model = 'qwen2.5:14b'
        # print(model)
        # localize(process, model, path)
        infer(process, model, path)
        # test(process, model, path)
        # output_prompt(model, path)
        # analyze_result(model, path)

def output_prompt(model, path):
    single_process(MetaManager, 'output_prompt', path, model)

def analyze_result(model, path=None):
    if path is not None:
        return
    with open(f'./case-analysis/{model}-result.txt', 'w') as f: ...
    single_process(MetaManager, 'output_result', path, model)
    model_list = ['deepseek-api', 'qwen2.5-coder:14b', 'codellama:13b', 'qwen2.5:14b']
    localization_model = [f'{i}@tracking.json' for i in model_list] + ['file', 'similarity']
    # infer_model = model_list
    # method_list = [f'{i} {j}' for j in localization_model for i in infer_model]
    # method_dict = {i: [0, 0] for i in method_list}
    # with open('./case-analysis/result.txt') as f:
    #     lines = f.readlines()
    # for line in lines:
    #     for method in method_list:
    #         if method in line:
    #             method_dict[method][1] += 1
    #             if 'True' in line:
    #                 method_dict[method][0] += 1
    # result = []
    # for method in method_list:
    #     # print(round(method_dict[method][0]/method_dict[method][1], 2), method_dict[method], method)
    #     result.append((round(method_dict[method][0]/method_dict[method][1], 2), method))
    # result.sort(key=lambda x: x[0])
    # for i in result:
    #     print(i)

def infer(process, model, path=None):
    # process(LLMHandler, 'infer', path)
    single_process(LLMHandler, 'model_infer', path, model)
    # multi_process(LLMHandler, 'model_infer', path, model)

def localize(process, model, path=None):
    # single_process(FaultLocalizer, 'localization_line_LLM', path, model)
    # single_process(FaultLocalizer, 'localization_line_log', path)
    # single_process(FaultLocalizer, 'localization_context', path)
    # process(FaultLocalizer, 'localization_context', path)
    # process(PromptManager, 'store_prompt_LLM_function_line_fault_localization', path, model)
    process(PromptManager, 'store_prompt_LLM_with_location', path, model)
    # process(PromptManager, 'store_prompt_fault_localization', path)
    # process(PromptManager, 'store_prompt_whole_file', path)

def test(process, model, path=None):
    process(TestManager, 'output_backport_result', path, model)
    # single_process(TestManager, 'output_backport_result', path)
    # if path is None:
    #     with open('./case-analysis/result.txt', 'w') as f: ...
    #     single_process(MetaManager, 'output_result', path)
    #     evaluation()
    #     length_study()

def length_study(granularity=None, path=None):
    if granularity is None:
        granularity = ['file', 'history', 'similarity']
    else: granularity = [granularity]
    for i in granularity:
        file_path = f'./case-analysis/{i}-case_analysis.txt'
        with open(file_path, 'w') as f: ...
        single_process(MetaManager, 'count_file_length', path, i)
        case_study(file_path)


def analyze_distribution_with_percentage(data):
    distribution_counts = OrderedDict([
        ("1-2", 0),
        ("3-4", 0),
        ("5-6", 0),
        ("7-8", 0),
        ("9-10", 0),
        ("11-20", 0),
        ("21-50", 0),
        ("51-100", 0),
        (">100", 0)
    ])
    
    total_valid_numbers = 0
    for number in data:
        if not isinstance(number, int) or number <= 0:
            continue
        
        total_valid_numbers += 1
        
        if number <= 2:
            distribution_counts["1-2"] += 1
        elif number <= 4:
            distribution_counts["3-4"] += 1
        elif number <= 6:
            distribution_counts["5-6"] += 1
        elif number <= 8:
            distribution_counts["7-8"] += 1
        elif number <= 10:
            distribution_counts["9-10"] += 1
        elif number <= 20:
            distribution_counts["11-20"] += 1
        elif number <= 50:
            distribution_counts["21-50"] += 1
        elif number <= 100:
            distribution_counts["51-100"] += 1
        else: # number > 100
            distribution_counts[">100"] += 1
        
    results = OrderedDict()

    if total_valid_numbers > 0:
        for category, count in distribution_counts.items():
            percentage = (count / total_valid_numbers) * 100
            results[category] = {'count': count, 'percentage': percentage}
    else:
        for category in distribution_counts:
            results[category] = {'count': 0, 'percentage': 0.0}

    return results, total_valid_numbers


def analyze_localzation_results(results):
    chunk_dict = defaultdict(list)
    vulnerability_dict = defaultdict(list)
    print(results)
    for chunk_results, vulnerability_results in results:
        for tool, result in chunk_results.items():
            if tool not in chunk_dict:
                chunk_dict[tool] = result
            else: chunk_dict[tool].extend(result)
        for tool, result in vulnerability_results.items():
            if tool not in vulnerability_dict:
                vulnerability_dict[tool] = [result]
            else: vulnerability_dict[tool].append(result)
    for tool in chunk_dict.keys():
        chunk_result = dict(Counter(chunk_dict[tool]))
        vulnerability_result = dict(Counter(vulnerability_dict[tool]))
        print(f'{tool}: & {chunk_result.get('Equal', 0)} & {chunk_result.get('Disjoint', 0)} & {chunk_result.get('Intersecting', 0)} & {chunk_result.get('Subset', 0)} & {chunk_result.get('Superset', 0)} & {vulnerability_result.get('Equal', 0)} & {vulnerability_result.get('Disjoint', 0)} & {vulnerability_result.get('Intersecting', 0)} & {vulnerability_result.get('Subset', 0)} & {vulnerability_result.get('Superset', 0)}')
    # for tool, result in chunk_dict.items():
    #     result = dict(Counter(result))
    #     print(f'{tool}: {result.get('Equal', 0)} & {result.get('Disjoint', 0)} & {result.get('Intersecting', 0)} & {result.get('Subset', 0)} & {result.get('Superset', 0)} &')
    # for tool, result in vulnerability_dict.items():
    #     result = dict(Counter(result))
    #     print(f'{tool}: {result.get('Equal', 0)} & {result.get('Disjoint', 0)} & {result.get('Intersecting', 0)} & {result.get('Subset', 0)} & {result.get('Superset', 0)}')

def analyze_chunks(results):
    print(analyze_distribution_with_percentage(results))

if __name__ == '__main__':
    # model_list = ['deepseek-api', 'qwen2.5-coder:14b', 'codellama:13b', 'qwen2.5:14b']
    # for model in model_list:
        # infer(single_process, model)
    # test(single_process)
    # output_prompt(None)
    # analyze_result()
    # single_process(PromptManager, 'store_prompt_LLM_function_line_fault_localization', '/data/SCA-repair/SecBench.js/code-injection/m-log_0.0.1')
    # whole_process('/data/SCA-repair/SecBench.js/redos/is-my-json-valid_2.20.1')
    # whole_process('/data/SCA-repair/SecBench.js/prototype-pollution/assign-deep_1.0.0')
    # whole_process('/data/SCA-repair/SecBench.js/redos/fresh_0.5.0')
    # single_process(MetaManager, 'compare_localization')
    # single_process(TestManager, 'output_baseline_result', None, 'mystique_codellama', './case-analysis/baseline_mystique_codellama.json')
    # whole_process('/data/SCA-repair/SecBench.js/command-injection/connection-tester_0.2.0')

    # with open('./error-log/record.log') as f:
    #     lines = [i.strip() for i in f.readlines()]
    # for i in lines:
    #     whole_process(i)
    whole_process('/data/SCA-repair/SecBench.js/redos/normalize-url_6.0.0')
    # single_process(MetaManager, 'output_line_chunk_line')