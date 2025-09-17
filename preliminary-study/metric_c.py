import json
import os
from concurrent.futures import ProcessPoolExecutor
from szz import repo_root_path, data_root_path
from szz import Metric
import logging
from szz import SZZ
import fcntl
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


result_file = './szz-result/szz_result_cV1.json'
# result_file = './C.json'

def load_result_c(file_path=result_file):
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        with open(file_path, 'w') as f:
            json.dump([], f)
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return data

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

def filter_c():
    data_path = os.path.join(data_root_path,'cve-c-patch.json')
    filtered_data = {}
    with open(data_path) as f:
        data = json.load(f)
    for cve_id, cve_item in data.items():
        repo_name = cve_item['repo']
        repo_path = os.path.join(repo_root_path, repo_name)
        if not os.path.exists(repo_path):
            continue
        filtered_data[cve_id] = cve_item
    written_path = os.path.join(data_root_path,'cve-c-patchV1.json')
    with open(written_path, 'w') as f:
        json.dump(filtered_data, f, ensure_ascii=False, indent=4)

def load_target_data_c():
    data_path = os.path.join(data_root_path,'cve-c-patchV1.json')
    with open(data_path) as f:
        data = json.load(f)
    return data

def metric_main():
    data = load_target_data_c()
    results = load_result_c()
    cves = [i['cve_id'] for i in results]
    for cve_id, cve_item in data.items():
        # if cve_id != "CVE-2021-0920":
        #     continue
        if cve_id in cves:
            continue
        process_cve_item(cve_id, cve_item)

def metric_main_multiprocessing():
    data = load_target_data_c()
    results = load_result_c()
    existing_cves = {i['cve_id'] for i in results}
    tasks = []
    for cve_id, cve_item in data.items():
        if cve_id in existing_cves:
            continue
        tasks.append((cve_id, cve_item))
    if not tasks:
        logging.info("All CVEs already processed.")
        return
    # for task in tasks:
    #     process_cve_item(*task)
    with ProcessPoolExecutor(max_workers=16) as executor:
        result = [executor.submit(process_cve_item, *task) for task in tasks]

def process_cve_item(cve_id, cve_item):
    logging.info(f'Processing {cve_id} in process {os.getpid()}...')
    patch_commit = cve_item['origin']
    target_commit = cve_item['target']
    repo_path = os.path.join(repo_root_path, cve_item['repo'])
    patch_url = f"https://www.github.com/{cve_item['owner']}/{cve_item['repo']}/commit/{patch_commit}"
    target_url = patch_url.replace(patch_commit, target_commit)
    # metric_item = Metric(cve_id, patch_commit, target_commit, None, repo_path, "c", patch_url)

    try:
        metric_item = Metric(cve_id, patch_commit, target_commit, None, repo_path, "c", patch_url)
        # write_result_lock(metric_item.result)
        write_result_lock(metric_item.time_gap, file_path='./motivation/c-commit-time.json')
        # write_result_lock(metric_item.file_items, file_path='c-file.json')
        # write_result_lock(metric_item.function_items, file_path='c-function.json')
    except Exception as e:
        logging.error(f"Error processing {cve_id}: {e}")
        return


def process_cve_item_szz(cve_id, cve_item):
    try:
        logging.info(f'Processing {cve_id} in process {os.getpid()}...')
        patch_commit = cve_item['origin']
        patch_url = f"https://github.com/{cve_item['owner']}/{cve_item['repo']}/commit/{patch_commit}"
        szz_item = SZZ(cve_id, patch_url)
        if szz_item.target_commit is None:
            with open('c-error.log', 'a') as f:
                f.write(f'{cve_id}: Skipping {cve_id}: target_commit not found\n')
            return
        else: 
            with open('c-error.log', 'a') as f:
                f.write(f'{cve_id}: target_commit found {szz_item.target_commit}\n')
        # print(szz_item.target_commit)
        metric_item = Metric(
            cve_id, 
            szz_item.commit_id, 
            szz_item.target_commit, 
            szz_item.target_lines, 
            szz_item.repo_path, 
            "c"
        )
        write_result_lock(metric_item.result, file_path='./szz-result/szz_result_cV1.json')
        # print(metric_item.file_items)
        # print(metric_item.function_items)
        # write_result_lock(metric_item.time_gap, file_path='./motivation/c-commit-time.json')
        write_result_lock(metric_item.function_items, file_path='./c-functionV1.json')
        write_result_lock(metric_item.file_items, file_path='./c-fileV1.json')
    except Exception as e:
        with open('c-error.log', 'a') as f:
            f.write(f"Error processing {cve_id}: {e}\n")
        return

def metric_main_multiprocessing_szz():
    data = load_target_data_c()
    results = load_result_c()
    existing_cves = {i['cve_id'] for i in results}
    with open('/data/SCA-repair/src/data-study/c-error.log') as f:
        coped_content = f.read()
    tasks = []
    for cve_id, cve_item in data.items():
        if cve_id in coped_content:
            continue
        tasks.append((cve_id, cve_item))
    if not tasks:
        logging.info("All CVEs already processed.")
        return
    # for task in tasks:
    #     process_cve_item_szz(*task)
    with ProcessPoolExecutor(max_workers=16) as executor:
        result = [executor.submit(process_cve_item_szz, *task) for task in tasks]

if __name__ == "__main__":
    metric_main_multiprocessing_szz()

    