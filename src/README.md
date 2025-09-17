# PatchPorter: LLM-Driven Security Patch Porting via Version Tracing and Context Selection for NPM

A sophisticated method for automatically backporting security vulnerability patches from patched versions to vulnerable versions of NPM packages using Large Language Models (LLMs) and advanced code analysis techniques.

## Overview




## Project Structure

```
open-source/src/
├── LLM_handler.py          # LLM interaction and API management
├── common_utils.py        # Common utility functions
├── fault_localizer.py     # Fault localization and code tracking
├── meta_manager.py        # Metadata and project management
├── project.py             # Project representation and utilities
├── prompt_manager.py      # Prompt generation and management
├── result_analyzer.py     # Result analysis and evaluation
├── task.py               # Main task orchestration
├── test_manager.py       # Testing and validation
└── untangler.py          # Patch untangling and decomposition
```

## Core Components

### 1. LLM Handler (`LLM_handler.py`)
- Manages interactions with various LLM providers (DeepSeekV3, GPT-4o, Gemini Flash, Ollama)
- Handles API calls, error handling, and response processing

### 2. Fault Localizer (`fault_localizer.py`)
- Tracks code changes across git history
- Maps patch locations from source to target versions
- Implements both traditional diff analysis and LLM-based semantic matching

### 3. Prompt Manager (`prompt_manager.py`)
- Generates context-aware prompts for LLMs
- Supports different context strategies (file, function, line)

### 4. Project Management (`project.py`)
- Represents individual software projects
- Manages basic information of the project

### 5. Test Manager (`test_manager.py`)
- Validates backported patches using Jest testing
- Provides comprehensive result analysis

## Usage

### Basic Workflow
1. **Project Setup**: Initialize project with vulnerable package information
2. **Patch Analysis**: Analyze the security patch to understand changes
3. **Fault Localization**: Identify corresponding code locations in target versions
4. **Prompt Generation**: Create context-aware prompts for LLM
5. **Patch Application**: Use LLM to generate and apply fixes
6. **Validation**: Test the backported patch for correctness

### Example Usage
```python
from task import whole_process

# Process a specific project
project_path = "/path/to/vulnerable/package"
whole_process(project_path)

# Or process all projects in a directory
whole_process()
```


