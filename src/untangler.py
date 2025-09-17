import shutil
import os
from common_utils import run_command

class untangler:
    def __init__(self, project):
        self.project = project
        self.prj_path = project.prj_path
        self.npm_prj_path = project.npm_prj_path
        self.patch_path = project.patch_path
        self.final_patch_path = project.final_patch_path
        self.patches_path = os.path.join(self.prj_path, 'patches')

    def untangle_from_filename(self):
        current_patch = self.project.get_unidiff_patch()
        self.patches = []
        self.hunks = []
        for patch in current_patch:
            if 'min.js' in patch.path or 'test' in patch.path or '.json' in patch.path or ('.js' not in patch.path and '.ts' not in patch.path and '.mjs' not in patch.path) or patch.is_added_file:
                continue
            self.patches.append(patch)
            for hunk in patch:
                self.hunks.append(hunk)

    def untangle_from_poc(self):
        print(self.prj_path)
        self.project.checkout_before_patch()
        hunks = self.generate_combinations(self.patch_path, self.prj_path)
        if len(hunks) == 1:
            write_patch(hunks, self.final_patch_path)
            return 
        patch_paths = [os.path.join(self.patches_path, i) for i in os.listdir(self.patches_path)]
        final_patches = []
        final_patch_indexs = []
        for patch_path in patch_paths:
            index = int(patch_path.split('_')[-1].split('.d')[0])
            run_command(f"git apply --ignore-whitespace {patch_path}", path=self.npm_prj_path)
            jest_result = self.project.jest()
            print(index, jest_result)
            if 'False' in jest_result:
                final_patches.append(hunks[index])
                final_patch_indexs.append(index)
            self.project.checkout('.')
        if len(final_patches) != 0:
            write_patch(final_patches, self.final_patch_path)
        else:
            write_patch(hunks, self.final_patch_path)

    def check_untangle_result(self):
        run_command(f"git apply --ignore-whitespace {self.final_patch_path}", path=self.npm_prj_path)

    def summarize_untangle(self):
        self.patch_filter()
        src_hunks = count_hunks_in_diff(self.patch_path) 
        filter_hunks = len(self.hunks)
        final_hunks = count_hunks_in_diff(self.final_patch_path)
        return (1, src_hunks, filter_hunks, final_hunks)

    def generate_combinations(self, patch_file, output_dir):
        if os.path.exists(self.patches_path):
            shutil.rmtree(self.patches_path)
        os.mkdir(self.patches_path)
        hunks = extract_hunks_with_metadata(patch_file)
        for i in range(0, len(hunks)):
            current_combination = hunks[0:i]+hunks[i+1:]
            write_patch(current_combination, f"{output_dir}/patches/patch_{i}.diff")
        return hunks

    def verify_untangle(self):
        final_patch = extract_hunks_with_metadata(self.final_patch_path)
        final_patch_bk = extract_hunks_with_metadata(self.final_patch_path+'.bk')
        if sorted(final_patch) != sorted(final_patch_bk):
            print(self.prj_path)
            print(self.final_patch_path)
            print(self.final_patch_path+'.bk')
            print()

def count_hunks_in_diff(diff_file_path, code_related=False):
    hunk_count = 0
    with open(diff_file_path, 'r') as file:
        for line in file:
            if line.startswith('@@'):
                hunk_count += 1
    return hunk_count

def extract_hunks_with_metadata(patch_file):
    hunks = []
    current_hunk = []
    metadata = []
    with open(patch_file, 'r') as file:
        for line in file:
            if line.startswith('diff') or line.startswith('index') or line.startswith('---') or line.startswith('+++') or line.startswith('deleted file') or line.startswith('new file'):
                if current_hunk:
                    hunks.append(metadata + current_hunk)
                    current_hunk = []
                    metadata = []
                metadata.append(line)
            elif line.startswith('@@'):
                if current_hunk:
                    hunks.append(metadata + current_hunk)
                    current_hunk = []
                current_hunk.append(line)
            else:
                current_hunk.append(line)
        if current_hunk:
            hunks.append(metadata + current_hunk)
    final_hunk = []
    for hunk in hunks:
        if 'min.js' in hunk[0] or 'test' in hunk[0] or '.json' in hunk[0] or ('.js' not in hunk[0] and '.ts' not in hunk[0] and '.mjs' not in hunk[0]):
            continue
        final_hunk.append(hunk)
    return final_hunk

def write_patch(hunks, output_file):
    with open(output_file, 'w') as file:
        for hunk in hunks:
            file.writelines(hunk)
