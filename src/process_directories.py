#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import shutil
import glob

def process_directories():
    # # 获取当前脚本所在目录的父目录（open-source目录）
    # script_dir = os.path.dirname(os.path.abspath(__file__))
    # open_source_dir = os.path.dirname(script_dir)
    # base_dir = os.path.dirname(open_source_dir)
    
    # 读取目录列表文件
    input_file = '/data/SCA-repair/data/jest-out-temp.txt'
    output_base = './open-source/dataset'
    
    # print(f"脚本目录: {script_dir}")
    # print(f"Open Source目录: {open_source_dir}")
    # print(f"基础目录: {base_dir}")
    print(f"输入文件: {input_file}")
    print(f"输出目录: {output_base}")
    
    # 确保输出基础目录存在
    os.makedirs(output_base, exist_ok=True)
    
    # 读取目录列表
    with open(input_file, 'r') as f:
        directories = [line.strip() for line in f if line.strip()]
    
    print(f"找到 {len(directories)} 个目录需要处理")
    
    for source_dir in directories:
        # 检查源目录是否存在
        if not os.path.exists(source_dir):
            print(f"警告: 目录不存在: {source_dir}")
            continue
        
        # 从完整路径中提取目录名
        dir_name = os.path.basename(source_dir)
        target_dir = os.path.join(output_base, dir_name)
        
        # 创建目标目录
        os.makedirs(target_dir, exist_ok=True)
        print(f"处理目录: {dir_name}")
        
        # 要提取的文件模式
        file_patterns = [
            'package.json',
            'final-patch.diff',
            'patch.diff',
            '*.test.js',
            'vulnerable_versions.txt',
            'challenge-version.txt'
        ]
        
        files_copied = 0
        
        # 遍历文件模式并复制文件
        for pattern in file_patterns:
            # 处理通配符模式
            if '*' in pattern:
                found_files = glob.glob(os.path.join(source_dir, pattern))
                for file_path in found_files:
                    if os.path.isfile(file_path):
                        file_name = os.path.basename(file_path)
                        target_path = os.path.join(target_dir, file_name)
                        shutil.copy2(file_path, target_path)
                        files_copied += 1
                        print(f"  复制: {file_name}")
            else:
                # 处理具体文件名
                file_path = os.path.join(source_dir, pattern)
                if os.path.isfile(file_path):
                    target_path = os.path.join(target_dir, pattern)
                    shutil.copy2(file_path, target_path)
                    files_copied += 1
                    print(f"  复制: {pattern}")
        
        if files_copied == 0:
            print(f"  警告: 在 {dir_name} 中没有找到任何目标文件")
        else:
            print(f"  成功复制 {files_copied} 个文件")
    
    print("处理完成!")

if __name__ == "__main__":
    process_directories()
