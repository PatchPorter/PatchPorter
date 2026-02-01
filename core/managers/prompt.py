"""
Prompt Manager for SCA-Repair.

Handles generation of LLM prompts for vulnerability patch backporting.
Supports multiple strategies:
- Line-based localization with dependency analysis
- Function-based localization
- File-based whole-file context
- Intelligent context selection based on variable usage
"""

import json
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple

from core.managers.base import BaseManager
from core.project import Project
from core.config import config
from core.utils.file import (
    read_file,
    read_lines,
    write_file,
    read_json,
    write_json,
    ensure_directory,
)
from core.utils.parsing import parse_localization_info
from core.utils.git import get_parent_commit
from core.exceptions import PromptGenerationError

logger = logging.getLogger(__name__)


class PromptTemplate:
    """Collection of prompt templates for different use cases."""
    
    BACKPORT_WITH_LOCALIZATION = '''You are a security vulnerability expert specializing in vulnerability analysis and repair. You excel at precisely porting security patches from one code version to another.
Core Task: Your task is to analyze a known vulnerability patch and accurately apply its core fix logic to the target vulnerable code. To help you better understand the code structure, I will provide the code context of the target code.
Input: 
- Vulnerability Patch: Source code differences (diff) containing the vulnerability fix logic.
- Target Vulnerable Code: The target vulnerable code snippet that needs to be fixed.
- Code Context: The code surrounding the target vulnerable code in the source file, provided for reference only to help you understand how to customize the patch application.
Output: 
- Fixed Target Code: ONLY the repaired target vulnerable code after applying the patch logic. DO NOT output the surrounding context code.
Requirements: 
1. Your modifications must strictly follow the fix logic in the vulnerability patch. Do not introduce any new features, code refactoring, or formatting adjustments that are unrelated to the code change of the patch.
2. CRITICAL: Your output should contain ONLY the modified target vulnerable code itself. The code context is for reference only to help you understand the structure and customize the patch. DO NOT include any context code in your output. Only output the minimal code segment that needs to be modified.
3. The final output must be pure code. Do not include any explanations or any descriptive text.
4. CRITICAL: Do NOT include any diff syntax symbols (such as +, -, @@) in your output. Output valid, executable code only.

Vulnerability Patch:
```
{patch}
```

Target Vulnerable Code:
```
{target_code}
```

Code Context:
```
{context}
```

Output:
'''

    BACKPORT_WITHOUT_CONTEXT = '''You are a security vulnerability expert specializing in vulnerability analysis and repair. You excel at precisely porting security patches from one code version to another.
Core Task: Your task is to analyze a known vulnerability patch and accurately apply its core fix logic to the target vulnerable code.
Input: 
- Vulnerability Patch: Source code differences (diff) containing the vulnerability fix logic.
- Target Vulnerable Code: The target vulnerable code snippet that needs to be fixed.
Output: 
- Fixed Target Code: ONLY the repaired target vulnerable code after applying the patch logic.
Requirements: 
1. Your modifications must strictly follow the fix logic in the vulnerability patch. Do not introduce any new features, code refactoring, or formatting adjustments that are unrelated to the code change of the patch.
2. CRITICAL: Your output should contain ONLY the modified target vulnerable code itself. Only output the minimal code segment that needs to be modified.
3. The final output must be pure code. Do not include any explanations or any descriptive text.
4. CRITICAL: Do NOT include any diff syntax symbols (such as +, -, @@) in your output. Output valid, executable code only.

Vulnerability Patch:
```
{patch}
```

Target Vulnerable Code:
```
{target_code}
```

Output:
'''

    BACKPORT_DELETION = '''You are a security vulnerability expert specializing in vulnerability analysis and repair. You excel at precisely porting security patches from one code version to another.
Core Task: The vulnerability patch contains DELETION operations. Your task is to analyze which code should be REMOVED to fix the vulnerability.
Input: 
- Vulnerability Patch: Source code differences showing lines to be DELETED (marked with -).
- Target Vulnerable Code: The current vulnerable code that needs to have lines removed.
Output: 
- Fixed Target Code: The code AFTER removing the vulnerable lines. If all lines should be deleted, output: [EMPTY]
Requirements: 
1. CRITICAL: Lines marked with "-" in the patch should be REMOVED from your output.
2. If the patch shows only deletions with no additions, DO NOT include those deleted lines in your output.
3. Your output must be executable code after deletion. Do not include explanations.
4. CRITICAL: Do NOT include any diff syntax symbols (such as +, -, @@) in your output.
5. If the entire target code is deleted, output exactly: [EMPTY]

Vulnerability Patch (lines to DELETE):
```
{patch}
```

Target Vulnerable Code:
```
{target_code}
```

Output the code after deletion:
'''

    BACKPORT_BASIC = '''You are an expert in the field of security vulnerabilities and are skilled at migrating vulnerability patches to other vulnerable versions of software.
Below are the task requirements:
Input: A vulnerability patch and code from another vulnerable version
Output: Code repaired according to the patch logic
Requirements:
1. Apply only the newly added code from the patch, without changing the original structure of the code.
2. Only output the code, no explanations
3. The repaired code should maintain the same syntactic structure as before the repair
4. CRITICAL: Do NOT include any diff syntax symbols (such as +, -, @@) in your output. Output valid, executable code only.


Vulnerability patch:
```
{patch}
```
Vulnerable code:
```
{target_code}
```
Output:
'''

    BACKPORT_WITH_LOCALIZATION_INSERT = '''You are a security vulnerability expert specializing in vulnerability analysis and repair. You excel at precisely porting security patches from one code version to another.
Core Task: The vulnerability patch contains only INSERTION operations (no deletions or modifications). Your task is to analyze the patch and insert the security fix at the appropriate location in the target code.
Input: 
- Vulnerability Patch: Source code differences (diff) containing the security fix logic to be inserted.
- Target Code Anchor: The code snippet that serves as a reference point (anchor) for where to insert the fix. This is NOT the code to be modified, but rather a location marker.
- Code Context: The code surrounding the target anchor in the source file, provided for reference only to help you understand how to customize the patch application.
Output: 
- Fixed Code: ONLY the modified target code anchor with the security fix inserted. DO NOT output the surrounding context code.
Requirements: 
1. This is an INSERTION operation. The target code anchor should remain unchanged, and you need to insert the patch logic near it at the appropriate position.
2. CRITICAL: Do NOT output the "<add here>" marker. It is only an internal anchor hint. Remove it from the final output.
3. Your modifications must strictly follow the fix logic in the vulnerability patch. Do not introduce any new features, code refactoring, or formatting adjustments that are unrelated to the code change of the patch.
4. CRITICAL: The code context is for reference only to help you understand the structure and customize the patch. DO NOT include any context code in your output. Only output the minimal code segment that contains the anchor and the inserted fix.
5. The final output must be pure code. Do not include any explanations or any descriptive text.
6. CRITICAL: Do NOT include any diff syntax symbols (such as +, -, @@) in your output. Output valid, executable code only.

Output Format Requirements (STRICT):
1. Output MUST contain two sections in this exact order:
    INSERT_BEFORE:
    (only the lines to insert)
    ANCHOR:
    (the original anchor code, unchanged)
2. Do NOT include any other text.

Vulnerability Patch:
```
{patch}
```

Target Code Anchor:
```
{target_code}
```

Code Context:
```
{context}
```

Output:
'''

    BACKPORT_WITH_LOCALIZATION_INSERT_NO_CONTEXT = '''You are a security vulnerability expert specializing in vulnerability analysis and repair. You excel at precisely porting security patches from one code version to another.
Core Task: The vulnerability patch contains only INSERTION operations (no deletions or modifications). Your task is to analyze the patch and insert the security fix at the appropriate location in the target code.
Input: 
- Vulnerability Patch: Source code differences (diff) containing the security fix logic to be inserted.
- Target Code Anchor: The code snippet that serves as a reference point (anchor) for where to insert the fix. This is NOT the code to be modified, but rather a location marker.
Output: 
- Fixed Code: ONLY the modified target code anchor with the security fix inserted.
Requirements: 
1. This is an INSERTION operation. The target code anchor should remain unchanged, and you need to insert the patch logic near it at the appropriate position.
2. CRITICAL: Do NOT output the "<add here>" marker. It is only an internal anchor hint. Remove it from the final output.
3. Your modifications must strictly follow the fix logic in the vulnerability patch. Do not introduce any new features, code refactoring, or formatting adjustments that are unrelated to the code change of the patch.
4. CRITICAL: Only output the minimal code segment that contains the anchor and the inserted fix.
5. The final output must be pure code. Do not include any explanations or any descriptive text.
6. CRITICAL: Do NOT include any diff syntax symbols (such as +, -, @@) in your output. Output valid, executable code only.

Output Format Requirements (STRICT):
1. Output MUST contain two sections in this exact order:
    INSERT_BEFORE:
    (only the lines to insert)
    ANCHOR:
    (the original anchor code, unchanged)
2. Do NOT include any other text.

Vulnerability Patch:
```
{patch}
```

Target Code Anchor:
```
{target_code}
```

Output:
'''

    BACKPORT_ONE_SHOT = '''You are an expert in the field of security vulnerabilities and are skilled at migrating vulnerability patches to other vulnerable versions of software.
Below are the task requirements:
Input: A vulnerability patch and code from another vulnerable version
Output: Code repaired according to the patch logic
Requirements:
1. Apply only the newly added code from the patch, without changing the original structure of the code.
2. Only output the code, no explanations
3. The repaired code should maintain the same syntactic structure as before the repair
4. CRITICAL: Do NOT include any diff syntax symbols (such as +, -, @@) in your output. Output valid, executable code only.

Here is an example:

Vulnerability patch:
```
function deepExtend(objects, collision, path) {{
       for (name in options) {{
         if (!options.hasOwnProperty(name))
           continue;
+        if (name === '__proto__')
+          continue;
 
         src = target[name];
         copy = options[name];
```
Vulnerable code:
```
      for (name in options) {{
        if (!options.hasOwnProperty(name))
          continue;

        src = target[name];
        copy = options[name];

        // Prevent never-ending loop
        if (target === copy) {{
          continue;
```
Output:
```
      for (name in options) {{
        if (!options.hasOwnProperty(name))
          continue;

        if (name === '__proto__')
          continue;
          
        src = target[name];
        copy = options[name];

        // Prevent never-ending loop
        if (target === copy) {{
          continue;
```

Now, please process the following input:
Vulnerability patch:
```
{patch}
```
Vulnerable code:
```
{target_code}
```
Output:
'''

    LINE_MAPPING = '''As a JavaScript code semantics expert, you are required to identify the code snippet from the target codebase that is most semantically similar to the given code.

Input: Target codebase and given code

Output:
The code from the target codebase that is most semantically similar to the given code

Output Format Requirements:
1. Output a Python-style list where each element contains only one line of content, e.g., [\'\'\'line A content\'\'\', \'\'\'line B content\'\'\'].
2. Do not use ``` or any explanatory text.
3. If no match is found, output [].

Now, process the following input:

Target codebase:

{target_code}

Given code:

{source_code}

The most semantically similar lines:
'''


class ChunkType:
    """Enumeration of diff chunk types."""
    ADD = "add"
    DELETE = "delete"
    MODIFY = "modify"


class PromptManager(BaseManager):
    """
    Manager for generating LLM prompts.
    
    Responsibilities:
    - Generate prompts for patch backporting
    - Incorporate localization information
    - Support multiple prompt strategies
    - Manage prompt file storage
    - Handle different chunk types (add/delete/modify)
    """
    
    def __init__(self, project: Project):
        """Initialize PromptManager."""
        super().__init__(project)
        
        self._prompt_path = self.project.prompt_path
        self._result_path = self.project.result_path
        self._patch_content = self.project.patch_content
        self._unidiff_patch = self.project.unidiff_patch
        self._patch_commit = self.project.patch_commit_id
        self._challenge_version = self.project.get_challenge_version()
        
        ensure_directory(self._prompt_path)
        ensure_directory(self._result_path)
    
    def validate(self) -> bool:
        """Validate that required data exists."""
        return (
            bool(self._patch_content)
            and bool(self._challenge_version)
        )
    
    def execute(self, **kwargs) -> Any:
        """Execute prompt generation based on method."""
        import time
        method = kwargs.get("method", "line")
        model = kwargs.get("model", "deepseek-api")
        context_granularity = kwargs.get("context_granularity", None)  # line, structure, function, file
        
        self._logger.info(f"=== Starting Prompt Generation (method: {method}, model: {model}, granularity: {context_granularity or 'dynamic'}) ===")
        start_time = time.time()
        
 # history_llm line_llm both use line-based prompt generation
        if method in ("line", "history_llm", "line_llm"):
            result = self.generate_line_prompts(model, method, context_granularity)
        elif method == "file":
            result = self.generate_file_prompts(method)
        elif method == "function":
            result = self.generate_function_prompts(model, method)
        else:
            result = None
        
        elapsed = time.time() - start_time
        if result:
            self._logger.info(f"Prompt generation completed in {elapsed:.2f}s, output: {result}")
        else:
            self._logger.warning(f"Prompt generation failed or returned None")
        
        # Store timing
        self.project._prompt_time = elapsed
        
        return result
    
    # =========================================================================
    # Prompt Generation
    # =========================================================================
    
    def generate_prompt_with_localization(
        self,
        patch: str,
        target_code: str,
        context: str,
        is_insert: bool = False,
        include_context: bool = True,
    ) -> str:
        """
        Generate a prompt with localization context.
        
        Args:
            patch: The vulnerability patch
            target_code: The target vulnerable code
            context: Surrounding code context
            is_insert: Whether this is an insertion-only operation
            
        Returns:
            Formatted prompt string
        """
        if is_insert:
            if include_context:
                return PromptTemplate.BACKPORT_WITH_LOCALIZATION_INSERT.format(
                    patch=patch,
                    target_code=target_code,
                    context=context,
                )
            return PromptTemplate.BACKPORT_WITH_LOCALIZATION_INSERT_NO_CONTEXT.format(
                patch=patch,
                target_code=target_code,
            )
        if include_context:
            return PromptTemplate.BACKPORT_WITH_LOCALIZATION.format(
                patch=patch,
                target_code=target_code,
                context=context,
            )
        return PromptTemplate.BACKPORT_WITHOUT_CONTEXT.format(
            patch=patch,
            target_code=target_code,
        )
    
    def generate_basic_prompt(
        self,
        patch: str,
        target_code: str,
    ) -> str:
        """
        Generate a basic backporting prompt.
        
        Args:
            patch: The vulnerability patch
            target_code: The target vulnerable code
            
        Returns:
            Formatted prompt string
        """
        return PromptTemplate.BACKPORT_BASIC.format(
            patch=patch,
            target_code=target_code,
        )
    
    def _analyze_chunk_type(self, hunk_content: str) -> str:
        """
        Analyze the type of a diff chunk.
        
        Args:
            hunk_content: The diff hunk content
        
        Returns:
            ChunkType: 'add', 'delete', or 'modify'
        """
        lines = [line for line in hunk_content.split('\n') if line.strip()]
        
        # Count additions and deletions (exclude file metadata)
        additions = sum(1 for l in lines if l.startswith('+') and not l.startswith('+++'))
        deletions = sum(1 for l in lines if l.startswith('-') and not l.startswith('---'))
        
        if deletions > 0 and additions == 0:
            return ChunkType.DELETE
        elif additions > 0 and deletions == 0:
            return ChunkType.ADD
        else:
            return ChunkType.MODIFY
    
    def _extract_deleted_lines(self, hunk_content: str) -> List[str]:
        """
        Extract lines that are deleted in the patch.
        
        Args:
            hunk_content: The diff hunk content
        
        Returns:
            List of deleted line contents (without the '-' prefix)
        """
        deleted = []
        for line in hunk_content.split('\n'):
            if line.startswith('-') and not line.startswith('---'):
                deleted.append(line[1:])  # Remove '-' prefix
        return deleted
    
    def generate_deletion_prompt(
        self,
        patch: str,
        target_code: str,
    ) -> str:
        """
        Generate a specialized prompt for deletion operations.
        
        Args:
            patch: Vulnerability patch showing deletions
            target_code: Target vulnerable code
        
        Returns:
            Formatted prompt string for deletion
        """
        return PromptTemplate.BACKPORT_DELETION.format(
            patch=patch,
            target_code=target_code,
        )
    
    def generate_one_shot_prompt(
        self,
        patch: str,
        target_code: str,
    ) -> str:
        """
        Generate a one-shot learning prompt with example.
        
        Args:
            patch: The vulnerability patch
            target_code: The target vulnerable code
            
        Returns:
            Formatted prompt string
        """
        return PromptTemplate.BACKPORT_ONE_SHOT.format(
            patch=patch,
            target_code=target_code,
        )
    
    # =========================================================================
    # Line-based Prompt Generation
    # =========================================================================
    
    def generate_line_prompts(self, model: str, method: str = "history_llm", context_granularity: Optional[str] = None) -> Optional[Path]:
        """
        Generate prompts using line-based localization.
        
        Args:
            model: Model identifier for localization file
            method: Localization method name (e.g., history_llm, line_llm)
            context_granularity: Context granularity (line, structure, function, file), None for dynamic
            
        Returns:
            Path to generated prompt file
        """
        self._logger.debug(f"Generating line-based prompts for model: {model}, method: {method}, granularity: {context_granularity or 'dynamic'}")
        
        # Oracle localization: read from localization.csv in project root
        if method == 'oracle':
            localization_path = self.project_path / 'localization.csv'
            self._logger.info(f"Using Oracle localization from: {localization_path}")
        else:
            localization_path = self.project.localization_path / f"{model}.csv"
        
        if not localization_path.exists():
            logger.warning(f"Localization file not found: {localization_path}")
            return None
        
        self._logger.debug(f"Parsing localization file: {localization_path}")
        commit_linos = parse_localization_info(str(localization_path))
        self._logger.debug(f"Found {len(commit_linos)} commits with localization data")
        
        # Find target version
        target_linos = None
        target_commit_id = None
        
        for commit_id, linos in commit_linos.items():
            version = self.project.find_version_by_commit(commit_id)
            if version == self._challenge_version:
                target_linos = linos
                target_commit_id = commit_id
                break
        
        if target_linos is None:
            logger.warning("No localization data for challenge version")
            return None
        
        # Process overlapped line numbers (auto-merge overlapping ranges)
        linos = self._process_overlapped_linos(target_linos)
        
        target_file_content = self.project.get_target_file_content(target_commit_id)
        target_file_lines = self.project.get_target_file_lines(target_commit_id)
        
        if not target_file_lines:
            logger.warning("Could not get target file content")
            return None
        
        prompts = []
        hunks = self._get_continuous_hunk_content()
        
        # Analyze dependencies to select appropriate context
        dependencies = self._analyze_hunk_dependencies() if len(hunks) > 0 else []
        
        # Determine customization method based on dependency analysis
        customization_method = "dynamic" if dependencies else "fixed"
        
        for index_str, lines in linos.items():
            # Handle empty localization: treat as new code insertion at file end
            if not lines:
                self._logger.debug(f"Chunk {index_str}: empty localization, treating as file-end insertion")
                lines = [-1]
            
            # Extract target code content
            if lines[0] == -1:
                target_content = target_file_lines[-1] if target_file_lines else ""
            else:
                lines = sorted(lines)
                start = max(0, lines[0] - 1)
                end = min(len(target_file_lines), lines[-1])
                target_content = "".join(target_file_lines[start:end])
            
            # Get corresponding hunks
            hunk_indices = [int(i) for i in index_str.split("@")]
            target_hunks = "\n".join(
                str(hunks[i]) for i in hunk_indices if i < len(hunks)
            )
            
            # Select context based on granularity setting or dependency analysis
            if context_granularity:
                # Use specified granularity (skip dependency analysis, use specified granularity directly)
                customization_method = context_granularity
                context = self._get_context_by_granularity(
                    context_granularity,
                    lines,
                    target_commit_id,
                    target_file_content or ""
                )
                self._logger.debug(
                    f"Hunk {index_str}: using {context_granularity} granularity, "
                    f"context size {len(context)} chars"
                )
            elif dependencies and hunk_indices and hunk_indices[0] < len(dependencies):
                # Use dependency analysis for dynamic context selection
                dep_level = dependencies[hunk_indices[0]]["dependent"]
                context = self._select_context_by_dependency(
                    hunk_indices[0],
                    lines,
                    target_commit_id,
                    dep_level
                )
                self._logger.debug(
                    f"Hunk {index_str}: dependency level {dep_level}, "
                    f"context size {len(context)} chars"
                )
            else:
                # Default context generation
                context = self._get_line_context(
                    target_file_content or "",
                    lines,
                )
            
            # Check if patch contains only additions (no deletions)
            # If so, add "<add here>" marker to indicate insertion operation
            vulnerable_code = target_content
            hunk_list = [line.strip() for line in target_hunks.split("\n") if line.strip()]
            has_add = any(line.startswith('+') for line in hunk_list)
            has_del = any(line.startswith('-') for line in hunk_list)
            is_insert_only = has_add and not has_del
            is_delete_only = has_del and not has_add
            
            # Analyze chunk type
            chunk_type = self._analyze_chunk_type(target_hunks)
            
            if is_insert_only:
                vulnerable_code = '<add here>\n' + vulnerable_code

            insert_lines = []
            if is_insert_only:
                for line in target_hunks.split("\n"):
                    if line.startswith('+'):
                        insert_lines.append(line[1:])
            
            include_context = context.strip() != target_content.strip()

            # Use appropriate prompt based on chunk type
            if chunk_type == ChunkType.DELETE:
                prompt = self.generate_deletion_prompt(
                    target_hunks,
                    vulnerable_code,
                )
            else:
                prompt = self.generate_prompt_with_localization(
                    target_hunks,
                    vulnerable_code,
                    context,
                    is_insert=is_insert_only,
                    include_context=include_context,
                )
            
            prompts.append({
                "prompt": prompt,
                "line": lines,
                "context": target_content,
                "is_insert_only": is_insert_only,
                "anchor_code": target_content,
                "insert_patch_lines": insert_lines,
            })
        
        # Optionally merge overlapping prompts
        # prompts = self._merge_prompts(prompts)
        
        # Generate output path with new naming scheme: {customization}@{localization}[-{model}].json
        # Include model name if explicitly specified
        if model and model != "deepseek-api":  # Only add model name if non-default
            output_path = self._prompt_path / f"{customization_method}@{method}-{model}.json"
        else:
            output_path = self._prompt_path / f"{customization_method}@{method}.json"
        
        # Save prompt file
        output_obj = {
            "prj_path": str(self.project_path),
            "version": self._challenge_version,
            "commit_id": target_commit_id,
            "prompt": prompts,
        }
        
        write_json(output_path, output_obj)
        logger.info(f"Generated {len(prompts)} prompts: {output_path}")
        
        return output_path
    
    def generate_file_prompts(self, method: str = "file") -> Optional[Path]:
        """
        Generate prompts using whole file as context.
        
        Args:
            method: Localization method name (default: file)
        
        Returns:
            Path to generated prompt file
        """
        challenge_commit = self.project.get_challenge_commit()
        if not challenge_commit:
            return None
        
        target_content = self.project.get_target_file_content(challenge_commit)
        if not target_content:
            return None
        
        # Check file length limit
        line_count = target_content.count("\n")
        if line_count > 500:
            logger.warning(f"File too long ({line_count} lines), skipping")
            return None
        
        # File method always uses full file context
        # Note: model parameter not available in this method signature
        output_path = self._prompt_path / f"file@{method}.json"
        
        prompt = self.generate_one_shot_prompt(
            self._patch_content,
            target_content,
        )
        
        output_obj = {
            "prj_path": str(self.project_path),
            "version": self._challenge_version,
            "commit_id": challenge_commit,
            "prompt": [{"prompt": prompt}],
        }
        
        write_json(output_path, output_obj)
        return output_path
    
    def generate_function_prompts(self, model: str, method: str = "function") -> Optional[Path]:
        """
        Generate prompts at function granularity.
        
        Args:
            model: Model identifier
            method: Localization method name (default: function)
            
        Returns:
            Path to generated prompt file
        """
        # This would use AST parsing to extract function-level context
        # Simplified implementation for now
        return self.generate_line_prompts(model, method)
    
    def generate_oracle_prompts(self, model: str = "deepseek-api") -> Optional[Path]:
        """
        Generate prompts using Oracle localization (localization.csv).
        
        Uses perfect localization from localization.csv file in project directory.
        This represents an upper bound on localization accuracy.
        
        Args:
            model: Model identifier
            
        Returns:
            Path to generated prompt file
        """
        # Check for localization.csv
        oracle_file = self.project_path / "localization.csv"
        if not oracle_file.exists():
            self._logger.warning(f"Oracle localization file not found: {oracle_file}")
            return None
        
        self._logger.info(f"Using Oracle localization from: {oracle_file}")
        
        # Parse Oracle localization
        linos = parse_localization_info(oracle_file)
        
        # Get challenge version
        challenge_commit = self.project.get_challenge_commit()
        if not challenge_commit:
            self._logger.error("Could not determine challenge version")
            return None
        
        # Find target lines for challenge version
        target_linos = None
        target_commit = None
        for commit_id, lines_dict in linos.items():
            version = self.project.find_version_by_commit(commit_id)
            if version == self._challenge_version:
                target_linos = lines_dict
                target_commit = commit_id
                break
        
        if not target_linos:
            self._logger.error(f"No Oracle localization found for challenge version: {self._challenge_version}")
            return None
        
        self._logger.info(f"Found Oracle localization for commit: {target_commit}")
        
        # Get file content and hunks
        target_file_content = self.project.get_target_file_content(target_commit)
        if not target_file_content:
            self._logger.error("Could not get target file content")
            return None
        
        hunks = self._get_continuous_hunk_content()
        dependencies = self._analyze_hunk_dependencies()
        
        # Generate prompts for each hunk
        prompts = []
        for index_str, lines in list(target_linos.items())[::-1]:
            hunk_indices = [int(i) for i in index_str.split('@')]
            target_hunks = '\n'.join([str(hunks[i]) for i in hunk_indices])
            
            if not lines or lines[0] == -1:
                # Empty localization
                target_content = target_file_content
                context = ""
            else:
                lines.sort()
                # Get target code
                file_lines = target_file_content.split("\n")
                start = max(0, lines[0] - 1)
                end = min(len(file_lines), lines[-1])
                target_content = "\n".join(file_lines[start:end])
                
                # Get context using dependency analysis
                if dependencies and hunk_indices and hunk_indices[0] < len(dependencies):
                    dep_level = dependencies[hunk_indices[0]]["dependent"]
                    context = self._select_context_by_dependency(
                        hunk_indices[0],
                        lines,
                        target_commit,
                        dep_level
                    )
                else:
                    context = self._get_function_scope_context(target_file_content, lines)
            
            # Check patch type
            vulnerable_code = target_content
            hunk_list = [line.strip() for line in target_hunks.split("\n") if line.strip()]
            has_add = any(line.startswith('+') for line in hunk_list)
            has_del = any(line.startswith('-') for line in hunk_list)
            is_insert_only = has_add and not has_del
            
            if is_insert_only:
                vulnerable_code = '<add here>\n' + vulnerable_code
            
            insert_lines = []
            if is_insert_only:
                for line in target_hunks.split("\n"):
                    if line.startswith('+'):
                        insert_lines.append(line[1:])
            
            include_context = context.strip() != target_content.strip()
            
            # Generate prompt
            chunk_type = self._analyze_chunk_type(target_hunks)
            if chunk_type == ChunkType.DELETE:
                prompt = self.generate_deletion_prompt(target_hunks, vulnerable_code)
            else:
                prompt = self.generate_prompt_with_localization(
                    target_hunks,
                    vulnerable_code,
                    context,
                    is_insert=is_insert_only,
                    include_context=include_context,
                )
            
            prompts.append({
                "prompt": prompt,
                "line": lines,
                "context": target_content,
                "is_insert_only": is_insert_only,
                "anchor_code": target_content,
                "insert_patch_lines": insert_lines,
            })
        
        # Save prompt file with oracle@ prefix
        output_path = self._prompt_path / f"oracle@{model}.json"
        
        output_obj = {
            "prj_path": str(self.project_path),
            "version": self._challenge_version,
            "commit_id": target_commit,
            "prompt": prompts,
        }
        
        write_json(output_path, output_obj)
        self._logger.info(f"Generated {len(prompts)} Oracle prompts: {output_path}")
        
        return output_path
    
    # =========================================================================
    # Helper Methods
    # =========================================================================
    
    def _get_continuous_hunk_content(self) -> List[str]:
        """
        Extract continuous change chunks from patch.
        
        Returns:
            List of hunk content strings
        """
        modifications = []
        
        for patched_file in self._unidiff_patch:
            for hunk in patched_file:
                current_chunk = []
                for line in hunk:
                    if "No newline at end of file" in line.value:
                        continue
                    if line.is_removed or line.is_added:
                        current_chunk.append(line.line_type + line.value)
                    else:
                        if current_chunk:
                            modifications.append("".join(current_chunk))
                        current_chunk = []
                if current_chunk:
                    modifications.append("".join(current_chunk))
        
        return modifications
    
    def _process_overlapped_linos(
        self,
        linos: Dict[str, List[int]],
    ) -> Dict[str, List[int]]:
        """
        Process and merge overlapping line numbers.
        
        Automatically merges hunks that have overlapping line ranges
        to avoid duplicate prompts for the same code region.
        
        Args:
            linos: Dictionary mapping hunk indices to line numbers
            
        Returns:
            Processed line numbers dictionary with merged overlaps
        """
        # Convert to groups with frozenset keys for merging
        merged_groups = [
            {frozenset([key]): set(values)} 
            for key, values in linos.items()
        ]
        
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
                    # Merge if line ranges overlap
                    if current_values & group_values:
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
        
        # Convert back to final format
        final_result = {}
        for group in merged_groups:
            group_keys, group_values = list(group.items())[0]
            final_key = "@".join(sorted(group_keys, key=int))
            final_result[final_key] = sorted(list(group_values))
        
        return final_result
    
    def _get_line_context(
        self,
        file_content: str,
        lines: List[int],
        context_size: int = 3,
    ) -> str:
        """
        Get context around specified lines.
        
        Args:
            file_content: Full file content
            lines: Line numbers to get context for
            context_size: Number of context lines before/after
            
        Returns:
            Context string
        """
        if not lines or lines[0] == -1:
            return file_content
        
        file_lines = file_content.split("\n")
        
        min_line = max(0, min(lines) - context_size - 1)
        max_line = min(len(file_lines), max(lines) + context_size)
        
        return "\n".join(file_lines[min_line:max_line])
    
    def _get_function_scope_context(
        self,
        file_content: str,
        lines: List[int],
    ) -> str:
        """
        Get the complete function scope containing the specified lines.
        
        Uses tree-sitter to find the enclosing function and return its full body.
        Falls back to line context if parsing fails.
        
        Args:
            file_content: Full file content
            lines: Line numbers to get context for
            
        Returns:
            Function scope or line context
        """
        if not lines or lines[0] == -1:
            return file_content
        
        try:
            from tree_sitter import Language, Parser
            import tree_sitter_javascript
            
            source_bytes = file_content.encode('utf-8')
            JS_LANGUAGE = Language(tree_sitter_javascript.language())
            parser = Parser(JS_LANGUAGE)
            tree = parser.parse(source_bytes)
            
            target_line = lines[0]  # Use first line as reference
            
            def find_enclosing_function(node, target_line_idx):
                """Find the smallest function containing the target line."""
                if node.type in ['function_declaration', 'function_expression', 
                                'arrow_function', 'method_definition']:
                    start_line = node.start_point[0] + 1
                    end_line = node.end_point[0] + 1
                    
                    if start_line <= target_line_idx <= end_line:
                        # Found a containing function, check children for nested functions
                        for child in node.children:
                            nested = find_enclosing_function(child, target_line_idx)
                            if nested:
                                return nested
                        # This is the innermost function
                        return node
                
                # Recursively search children
                for child in node.children:
                    result = find_enclosing_function(child, target_line_idx)
                    if result:
                        return result
                return None
            
            function_node = find_enclosing_function(tree.root_node, target_line)
            
            if function_node:
                # Extract function scope
                function_text = source_bytes[function_node.start_byte:function_node.end_byte].decode('utf8')
                return function_text
            else:
                # Not in a function, return broader context
                return self._get_line_context(file_content, lines, context_size=10)
                
        except Exception as e:
            self._logger.debug(f"Failed to parse function scope: {e}, falling back to line context")
            return self._get_line_context(file_content, lines, context_size=10)
    
    def _get_structure_context(
        self,
        file_content: str,
        lines: List[int],
    ) -> str:
        """
        Get the minimal structure containing the specified lines.
        
        Uses tree-sitter to find the enclosing statement-level structure.
        Falls back to line context if parsing fails.
        
        Args:
            file_content: Full file content
            lines: Line numbers to get context for
            
        Returns:
            Structure context or line context
        """
        if not lines or lines[0] == -1:
            return file_content
        
        try:
            from tree_sitter import Language, Parser
            import tree_sitter_javascript
            
            source_bytes = file_content.encode('utf-8')
            JS_LANGUAGE = Language(tree_sitter_javascript.language())
            parser = Parser(JS_LANGUAGE)
            tree = parser.parse(source_bytes)
            
            target_line = lines[0]  # Use first line as reference
            
            def find_minimal_structure(node, target_line_idx):
                """Find the smallest structure containing the target line."""
                # Check if node contains target line
                start_line = node.start_point[0] + 1
                end_line = node.end_point[0] + 1
                
                if not (start_line <= target_line_idx <= end_line):
                    return None
                
                # Try to find smaller child node
                smallest_child = None
                for child in node.children:
                    result = find_minimal_structure(child, target_line_idx)
                    if result:
                        smallest_child = result
                        break
                
                # If found smaller child, return it
                if smallest_child:
                    return smallest_child
                
                # If current node is statement-level, return it
                statement_types = [
                    'expression_statement',
                    'variable_declaration',
                    'lexical_declaration',
                    'if_statement',
                    'for_statement',
                    'while_statement',
                    'return_statement',
                    'throw_statement',
                    'try_statement',
                    'switch_statement',
                    'assignment_expression',
                    'call_expression',
                ]
                
                if node.type in statement_types:
                    return node
                
                # Otherwise return current node
                return node
            
            structure_node = find_minimal_structure(tree.root_node, target_line)
            
            if structure_node:
                structure_text = source_bytes[structure_node.start_byte:structure_node.end_byte].decode('utf8')
                return structure_text
            else:
                # Fallback to line context
                return self._get_line_context(file_content, lines, context_size=3)
                
        except Exception as e:
            self._logger.debug(f"Failed to parse structure: {e}, falling back to line context")
            return self._get_line_context(file_content, lines, context_size=3)
    
    def _get_context_by_granularity(
        self,
        granularity: str,
        lines: List[int],
        target_commit: str,
        file_content: str,
    ) -> str:
        """
        Get context based on specified granularity.
        
        Args:
            granularity: One of 'line', 'structure', 'function', 'file'
            lines: Target line numbers
            target_commit: Commit to get content from
            file_content: Full file content
            
        Returns:
            Context string
        """
        if granularity == "line":
            # Only the localized lines, no additional context
            if not lines or lines[0] == -1:
                return file_content
            file_lines = file_content.split("\n")
            start = max(0, lines[0] - 1)
            end = min(len(file_lines), lines[-1])
            return "\n".join(file_lines[start:end])
        
        elif granularity == "structure":
            # Minimal containing structure (statement/expression)
            return self._get_structure_context(file_content, lines)
        
        elif granularity == "function":
            # Complete function scope
            return self._get_function_scope_context(file_content, lines)
        
        elif granularity == "file":
            # Entire file
            return file_content
        
        else:
            # Unknown granularity, fallback to line with context
            self._logger.warning(f"Unknown granularity '{granularity}', using line context")
            return self._get_line_context(file_content, lines, context_size=3)
    
    def _merge_target_contexts(
        self,
        contexts: Dict[int, str],
    ) -> str:
        """
        Merge multiple contexts, avoiding duplicates.
        
        Args:
            contexts: Dictionary mapping line numbers to contexts
            
        Returns:
            Merged context string
        """
        merged = []
        
        for line, context in sorted(contexts.items()):
            # Check if context is already included
            is_subset = any(context in existing for existing in merged)
            if not is_subset:
                merged.append(context)
        
        return "\n".join(merged)
    
    def _analyze_hunk_dependencies(self) -> List[Dict[str, Any]]:
        """
        Analyze variable dependencies between hunks.
        
        Determines whether each hunk introduces new variables that are
        not defined elsewhere, helping decide the appropriate context scope.
        
        Returns:
            List of dependency analysis results, one per hunk
            Each result contains: {"dependent": int, "pre_def_use": dict, "post_def_use": dict}
            dependent values:
              0 = needs full file context (undefined variables)
              1 = needs extended context (variables defined in other hunks)
              2 = self-contained (all variables defined locally)
        """
        from tree_sitter import Language, Parser
        import tree_sitter_javascript
        
        white_list = [
            'Error', 'Object', 'Array', 'isNaN', 'parseInt', 
            'require', 'console', 'TypeError', 'JSON', 'String',
            'Number', 'Boolean', 'undefined', 'null', 'Math'
        ]
        
        chunks = self._get_continuous_hunks_with_lines()
        
        # Get file content before and after patch
        pre_file = self.project.get_target_file_content(
            get_parent_commit(self._patch_commit, self.project.npm_project_path)
        )
        post_file = self.project.get_target_file_content(self._patch_commit)
        
        if not pre_file or not post_file:
            return []
        
        results = []
        for pre_lines, post_lines in chunks:
            dependent = 2  # Assume self-contained initially
            
            pre_def_use = self._get_def_use_from_lines(
                pre_lines, pre_file
            )
            post_def_use = self._get_def_use_from_lines(
                post_lines, post_file
            )
            
            # Check if post-patch code uses undefined variables
            for var in post_def_use['use']:
                if (var not in post_def_use['def'] and 
                    var not in white_list and
                    var not in pre_def_use['use'] and 
                    var not in pre_def_use['def']):
                    dependent = 0  # Needs full context
                    break
            
            results.append({
                "dependent": dependent,
                "pre_def_use": pre_def_use,
                "post_def_use": post_def_use
            })
        
        # Second pass: check if undefined vars are defined in other hunks
        for i, result in enumerate(results):
            if result["dependent"] == 0:
                post_def_use = result["post_def_use"]
                dependent = 1  # Try extended context first
                
                for var in post_def_use['use']:
                    if (var not in post_def_use['def'] and 
                        var not in white_list):
                        # Check if defined in other hunks
                        found_in_other = any(
                            var in r['pre_def_use']['use'] or
                            var in r['post_def_use']['def'] or
                            var in r['pre_def_use']['def']
                            for j, r in enumerate(results) if j != i
                        )
                        if not found_in_other:
                            dependent = 0  # Still needs full file
                            break
                
                result["dependent"] = dependent
        
        return results
    
    def _get_continuous_hunks_with_lines(self) -> List[Tuple[List[int], List[int]]]:
        """
        Extract continuous change chunks with line numbers.
        
        Returns:
            List of (pre_lines, post_lines) tuples
        """
        modifications = []
        
        for patched_file in self._unidiff_patch:
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
                            modifications.append(
                                (current_delete, current_add)
                            )
                        current_delete = []
                        current_add = []
                
                if current_delete or current_add:
                    modifications.append((current_delete, current_add))
        
        return modifications
    
    def _get_def_use_from_lines(
        self, 
        lines: List[int], 
        file_content: str
    ) -> Dict[str, List[str]]:
        """
        Extract defined and used variables from specific lines using AST.
        
        Args:
            lines: Line numbers to analyze
            file_content: Full file content
            
        Returns:
            Dictionary with 'def' and 'use' keys containing variable names
        """
        from tree_sitter import Language, Parser
        import tree_sitter_javascript
        
        result = {"def": [], "use": []}
        
        if not lines:
            return result
        
        try:
            JS_LANGUAGE = Language(tree_sitter_javascript.language())
            parser = Parser(JS_LANGUAGE)
            tree = parser.parse(file_content.encode('utf-8'))
            root_node = tree.root_node
            
            line_start = min(lines)
            line_end = max(lines)
            
            def traverse(node):
                # Check if node is in target line range
                node_start = node.start_point[0] + 1
                node_end = node.end_point[0] + 1
                
                if node_start > line_end or node_end < line_start:
                    return  # Skip nodes outside range
                
                # Variable definitions
                if node.type in ['variable_declarator', 'lexical_declaration', 'variable_declaration']:
                    for child in node.children:
                        if child.type == 'identifier':
                            var_name = child.text.decode('utf8')
                            if var_name not in result["def"]:
                                result["def"].append(var_name)
                
                # Function declarations
                elif node.type == 'function_declaration':
                    name_node = node.child_by_field_name('name')
                    if name_node:
                        func_name = name_node.text.decode('utf8')
                        if func_name not in result["def"]:
                            result["def"].append(func_name)
                
                # Function parameters
                elif node.type == 'formal_parameters':
                    for child in node.children:
                        if child.type == 'identifier':
                            param_name = child.text.decode('utf8')
                            if param_name not in result["def"]:
                                result["def"].append(param_name)
                
                # Variable usage
                elif node.type == 'identifier':
                    parent = node.parent
                    if parent and parent.type not in ['member_expression', 'property_identifier']:
                        var_name = node.text.decode('utf8')
                        if var_name not in result["use"]:
                            result["use"].append(var_name)
                
                # Recurse to children
                for child in node.children:
                    traverse(child)
            
            traverse(root_node)
        except Exception as e:
            self._logger.warning(f"AST parsing failed: {e}")
        
        return result
    
    def _select_context_by_dependency(
        self,
        hunk_index: int,
        lines: List[int],
        target_commit: str,
        dependency_level: int,
    ) -> str:
        """
        Select appropriate context based on dependency analysis.
        
        Args:
            hunk_index: Index of the hunk
            lines: Target line numbers
            target_commit: Commit to get content from
            dependency_level: Result from dependency analysis
                0 = function scope (has undefined variables, modified to use function context)
                1 = extended context (variables defined in other hunks)
                2 = self-contained (no additional context needed)
            
        Returns:
            Context string
        """
        target_file_content = self.project.get_target_file_content(target_commit)
        
        if not target_file_content:
            return ""
        
        if dependency_level == 0:
            # Modified: use function scope instead of full file
            # This provides the complete lexical scope for understanding variable usage
            return self._get_function_scope_context(target_file_content, lines)
        elif dependency_level == 1:
            # Extended context - try to get function scope first
            # This provides the complete lexical scope for understanding variable usage
            return self._get_function_scope_context(target_file_content, lines)
        else:
            # Self-contained (dependency == 2) - use target lines only
            # No additional context needed as all variables are locally defined
            target_file_lines = target_file_content.split("\n")
            if not lines or lines[0] == -1:
                return target_file_content
            
            start = max(0, lines[0] - 1)
            end = min(len(target_file_lines), lines[-1])
            return "\n".join(target_file_lines[start:end])
    
    def _merge_prompts(
        self, 
        prompts: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Merge prompts with overlapping contexts to reduce redundancy.
        
        Args:
            prompts: List of prompt dictionaries
            
        Returns:
            Merged list of prompts
        """
        # Sort by context length (longest first)
        prompts.sort(key=lambda x: len(x.get('context', '')), reverse=True)
        
        merged = []
        
        for prompt in prompts:
            context = prompt.get('context', '')
            patch = prompt.get('patch', '')
            
            # Try to find existing prompt that contains this context
            found = False
            for existing in merged:
                existing_context = existing.get('context', '')
                
                if context in existing_context and context:
                    # Context already covered, just add patch
                    if 'patches' not in existing:
                        existing['patches'] = [existing.pop('patch', '')]
                    if patch not in existing['patches']:
                        existing['patches'].append(patch)
                    found = True
                    break
                elif existing_context in context and existing_context:
                    # New context is larger, replace
                    existing['context'] = context
                    if 'patches' not in existing:
                        existing['patches'] = [existing.pop('patch', '')]
                    if patch not in existing['patches']:
                        existing['patches'].append(patch)
                    found = True
                    break
            
            if not found:
                merged.append(prompt.copy())
        
        # Convert patches lists back to strings
        for p in merged:
            if 'patches' in p:
                p['patch'] = '\n```\n```\n'.join(p['patches'])
                del p['patches']
        
        return merged
