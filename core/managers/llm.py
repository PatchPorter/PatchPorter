"""
LLM Handler for SCA-Repair.

Provides a unified interface for interacting with various LLM providers,
including API-based models (DeepSeek, GPT-4, Gemini).
"""

import json
import logging
import time
from pathlib import Path
from typing import Optional, List, Dict, Any, Callable
from dataclasses import dataclass, field

from core.managers.base import BaseManager
from core.project import Project
from core.config import config
from core.utils.file import read_json, write_json
from core.exceptions import LLMInferenceError, APIRequestFailedError

logger = logging.getLogger(__name__)


@dataclass
class InferenceResult:
    """Result of an LLM inference call."""
    
    output: str
    model: str
    prompt_length: int
    tokens_used: Optional[int] = None
    duration_ms: Optional[float] = None
    cost: Optional[float] = None


@dataclass
class ModelConfig:
    """Configuration for a specific model."""
    
    name: str
    provider: str  # 'openai', 'deepseek', 'gemini'
    max_prompt_length: int = 25000
    temperature: float = 0.0
    api_key: Optional[str] = None
    base_url: Optional[str] = None


class LLMHandler(BaseManager):
    """
    Handler for LLM inference operations.
    
    Supports multiple backends:
    - DeepSeek API
    - OpenAI API (GPT-4)
    - Gemini API
    
    Features:
    - Automatic model selection
    - Retry with exponential backoff
    - Prompt length validation
    - Token usage tracking
    """
    
    # Model registry mapping names to configurations
    MODEL_CONFIGS = {
        "deepseek-api": ModelConfig(
            name="deepseek-chat",
            provider="deepseek",
            max_prompt_length=50000,
        ),
        "deepseek-reasoner": ModelConfig(
            name="deepseek-reasoner",
            provider="deepseek",
            max_prompt_length=50000,
        ),
        "gpt4o": ModelConfig(
            name="gpt-4o",
            provider="openai",
            max_prompt_length=100000,
        ),
        "gpt-5": ModelConfig(
            name="gpt-5",
            provider="openai",
            max_prompt_length=100000,
            temperature=1.0,  # GPT-5 only supports temperature=1
        ),
        "gemini": ModelConfig(
            name="gemini-2.5-flash",
            provider="openai",  # Using OpenAI-compatible endpoint
            max_prompt_length=100000,
        ),
        "gemini-3-flash-preview": ModelConfig(
            name="gemini-3-flash-preview",
            provider="openai",  # Using OpenAI-compatible endpoint
            max_prompt_length=100000,
        ),
        "qwen3-14b": ModelConfig(
            name="qwen3-14b",
            provider="openai",  # Using OpenAI-compatible endpoint
            max_prompt_length=100000,
        ),
        "claude-sonnet-4-5-20250929": ModelConfig(
            name="claude-sonnet-4-5-20250929",
            provider="openai",  # Using OpenAI-compatible endpoint
            max_prompt_length=100000,
        ),
    }
    
    def __init__(self, project: Project):
        """Initialize LLMHandler."""
        super().__init__(project)
        
        self._challenge_version = self.project.get_challenge_version()
        self._prompt_path = self.project.prompt_path
        self._default_models = ["deepseek-api"]
        self._cost_tracking: Dict[str, float] = {}
    
    def validate(self) -> bool:
        """Validate that prompt files exist."""
        return self._prompt_path.exists()
    
    def execute(self, **kwargs) -> Any:
        """Execute inference for a model."""
        model = kwargs.get("model", "deepseek-api")
        return self.infer_for_model(model)
    
    # =========================================================================
    # Model Inference
    # =========================================================================
    
    def infer(self, content: str, model: str = "deepseek-api") -> str:
        """
        Perform inference with the specified model.
        
        Args:
            content: Prompt content
            model: Model identifier
            
        Returns:
            Model output as string
            
        Raises:
            LLMInferenceError: If inference fails
        """
        self._logger.debug(f"Starting inference with model: {model}, prompt length: {len(content)}")
        model_config = self._get_model_config(model)
        self._logger.debug(f"Provider: {model_config.provider}, max length: {model_config.max_prompt_length}")
        
        # Initialize tracking for this inference
        if not hasattr(self, '_inference_tokens'):
            self._inference_tokens = 0
        
        # Validate prompt length
        if len(content) > model_config.max_prompt_length:
            logger.warning(
                f"Prompt length {len(content)} exceeds max {model_config.max_prompt_length}"
            )
            return ""
        
        start_time = time.time()
        try:
            if model_config.provider == "deepseek":
                output = self._infer_deepseek(content, model_config)
            elif model_config.provider == "openai":
                if "gemini" in model.lower():
                    output = self._infer_gemini(content, model_config)
                else:
                    output = self._infer_openai(content, model_config)
            else:
                raise LLMInferenceError(
                    f"Unknown provider: {model_config.provider}",
                    model=model,
                )
            
            duration = (time.time() - start_time) * 1000
            self._logger.info(f"Inference completed in {duration:.0f}ms, output length: {len(output)}")
            return output
        except Exception as e:
            logger.error(f"Inference failed for {model}: {e}")
            raise LLMInferenceError(
                str(e),
                model=model,
                prompt_length=len(content),
            )
    
    def _get_model_config(self, model: str) -> ModelConfig:
        """Get configuration for a model."""
        if model in self.MODEL_CONFIGS:
            return self.MODEL_CONFIGS[model]
        
        # Unknown model - raise error
        raise LLMInferenceError(
            f"Unknown model: {model}. Available models: {list(self.MODEL_CONFIGS.keys())}",
            model=model)
    # =========================================================================
    # Post-processing for Special Cases
    # =========================================================================
    
    def post_process_output(
        self,
        output: str,
        chunk_type: str,
        patch_content: str,
        original_target: str,
    ) -> str:
        """
        Post-process LLM output based on chunk type.
        
        Args:
            output: Raw LLM output
            chunk_type: Type of chunk ('add', 'delete', 'modify')
            patch_content: Original patch content
            original_target: Original target vulnerable code
            
        Returns:
            Processed output
        """
        if chunk_type == "delete":
            return self._post_process_deletion(output, patch_content, original_target)
        return output
    
    def _post_process_deletion(
        self,
        llm_output: str,
        patch_content: str,
        original_target: str,
    ) -> str:
        """
        Post-process deletion operations.
        
        Args:
            llm_output: LLM output
            patch_content: Patch showing deletions
            original_target: Original target code
            
        Returns:
            Validated output with deletions properly applied
        """
        # Handle [EMPTY] marker
        if llm_output.strip() == "[EMPTY]":
            return ""
        
        # Extract lines that should be deleted
        deleted_lines = []
        for line in patch_content.split('\n'):
            if line.startswith('-') and not line.startswith('---'):
                deleted_lines.append(line[1:].strip())
        
        # Verify deletions were applied
        output = llm_output
        for deleted_line in deleted_lines:
            if deleted_line and deleted_line in output:
                logger.warning(f"LLM failed to delete line: {deleted_line[:50]}...")
                # Force deletion
                output = output.replace(deleted_line, "")
        
        # Clean up extra blank lines
        output = self._clean_empty_lines(output)
        
        # If output matches original, LLM didn't apply deletion
        if output.strip() == original_target.strip():
            logger.error("LLM did not apply deletion, returning empty")
            return ""
        
        return output
    
    def _clean_empty_lines(self, code: str) -> str:
        """Remove excessive empty lines."""
        lines = code.split('\n')
        cleaned = []
        prev_empty = False
        
        for line in lines:
            if line.strip():
                cleaned.append(line)
                prev_empty = False
            elif not prev_empty:
                cleaned.append(line)
                prev_empty = True
        
        return '\n'.join(cleaned)
    
    def _remove_think_tags(self, text: str) -> str:
        """
        Remove <think>...</think> tags from LLM output.
        
        Some models output thinking process in XML-like tags even when
        enable_thinking is set to False. This method strips those tags.
        """
        import re
        # Remove <think>...</think> blocks (non-greedy match, handles multiline)
        cleaned = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL)
        # Clean up extra whitespace left after removal
        cleaned = re.sub(r'\n\n+', '\n\n', cleaned)
        return cleaned.strip()
    
    # =========================================================================
    # Provider-specific Implementations
    # =========================================================================
    
    def _infer_deepseek(self, content: str, model_config: ModelConfig) -> str:
        """Inference using DeepSeek API."""
        try:
            from openai import OpenAI
        except ImportError:
            raise LLMInferenceError(
                "OpenAI client not installed. Install with: pip install openai",
                model=model_config.name,
            )
        
        api_key = config.llm.deepseek_api_key
        if not api_key:
            raise LLMInferenceError(
                "DeepSeek API key not configured",
                model=model_config.name,
            )
        
        client = OpenAI(
            api_key=api_key,
            base_url=config.llm.deepseek_base_url,
        )
        
        response = client.chat.completions.create(
            model=model_config.name,
            messages=[
                {"role": "user", "content": content},
            ],
            stream=False,
            temperature=model_config.temperature,
            # extra_body={"enable_thinking": False},  # Disable thinking for non-streaming calls
        )
        
        # Track tokens
        if response.usage:
            tokens = response.usage.total_tokens
            self._inference_tokens += tokens
            self._track_cost(model_config.name, tokens)
        
        return response.choices[0].message.content or ""
    
    def _infer_openai(self, content: str, model_config: ModelConfig) -> str:
        """Inference using OpenAI API."""
        try:
            from openai import OpenAI
        except ImportError:
            raise LLMInferenceError(
                "OpenAI client not installed. Install with: pip install openai",
                model=model_config.name,
            )
        
        api_key = config.llm.openai_api_key
        if not api_key:
            raise LLMInferenceError(
                "OpenAI API key not configured",
                model=model_config.name,
            )
        
        client = OpenAI(
            api_key=api_key,
            base_url=config.llm.openai_base_url,
        )
        
        # Only qwen3-14b requires enable_thinking=False parameter
        extra_params = {}
        if "qwen3-14b" in model_config.name.lower():
            extra_params = {"enable_thinking": False}
        
        response = client.chat.completions.create(
            model=model_config.name,
            messages=[
                {"role": "user", "content": content},
            ],
            stream=False,
            temperature=model_config.temperature,
            extra_body=extra_params,
        )
        
        # Track token usage
        if response.usage:
            tokens = response.usage.total_tokens
            self._inference_tokens += tokens
            self._track_cost(
                model_config.name,
                tokens,
            )
        
        output = response.choices[0].message.content or ""
        # Remove <think> tags if present (some models ignore enable_thinking parameter)
        output = self._remove_think_tags(output)
        return output
    
    def _infer_gemini(
        self, 
        content: str, 
        model_config: ModelConfig,
        max_retries: int = 10,
    ) -> str:
        """Inference using Gemini API with retry logic."""
        try:
            from openai import OpenAI
            import openai
        except ImportError:
            raise LLMInferenceError(
                "OpenAI client not installed. Install with: pip install openai",
                model=model_config.name,
            )
        
        api_key = config.llm.openai_api_key
        if not api_key:
            raise LLMInferenceError(
                "OpenAI API key not configured (for Gemini proxy)",
                model=model_config.name,
            )
        
        client = OpenAI(
            api_key=api_key,
            base_url=config.llm.openai_base_url,
        )
        
        for attempt in range(max_retries):
            try:
                response = client.chat.completions.create(
                    model=model_config.name,
                    messages=[
                        {"role": "user", "content": content},
                    ],
                    stream=False,
                    temperature=model_config.temperature,
                )
                
                if response.usage:
                    tokens = response.usage.total_tokens
                    self._inference_tokens += tokens
                    self._track_cost(
                        model_config.name,
                        tokens,
                    )
                
                output = response.choices[0].message.content or ""
                # Remove <think> tags if present (some models ignore enable_thinking parameter)
                output = self._remove_think_tags(output)
                return output
                
            except openai.InternalServerError:
                logger.warning(
                    f"Gemini API error, retry {attempt + 1}/{max_retries}"
                )
                time.sleep(2 ** attempt)
            except Exception as e:
                raise LLMInferenceError(str(e), model=model_config.name)
        
        raise APIRequestFailedError(
            f"API request failed after {max_retries} retries",
            model=model_config.name,
            retries=max_retries,
        )
    
    # =========================================================================
    # Batch Processing
    # =========================================================================
    
    def infer_for_model(self, model: str) -> List[str]:
        """
        Run inference for all prompts with a specific model.
        
        Args:
            model: Model identifier
            
        Returns:
            List of outputs
        """
        import time
        prompt_files = list(self._prompt_path.glob("*.json"))
        
        # Reset inference tracking
        self._inference_tokens = 0
        inference_start = time.time()
        
        for prompt_file in prompt_files:
            # Filter: only process files related to current model
            # File format: {customization}@{method}[-{model}].json
            # If file contains model suffix and doesn't match current model, skip
            file_stem = prompt_file.stem
            
            # Check if file has model-specific suffix
            if "_llm-" in file_stem or file_stem.endswith(tuple(f"-{m}" for m in self.MODEL_CONFIGS.keys())):
                # Extract model from filename
                file_model = None
                if "_llm-" in file_stem:
                    # Format: xxx_llm-{model}
                    file_model = file_stem.split("_llm-", 1)[1]
                else:
                    # Format: xxx-{model}
                    for model_name in self.MODEL_CONFIGS.keys():
                        if file_stem.endswith(f"-{model_name}"):
                            file_model = model_name
                            break
                
                # Skip if file is for a different model
                if file_model and file_model != model:
                    logger.debug(f"Skipping {prompt_file.name} (for model: {file_model})")
                    continue
            
            try:
                json_content = read_json(prompt_file)
            except Exception as e:
                logger.error(f"Failed to read {prompt_file}: {e}")
                continue
            
            # Always reprocess - overwrite existing output
            output_key = f"{model}-output"
            
            logger.info(f"Processing {prompt_file.name}")
            outputs = []
            
            for prompt_item in json_content.get("prompt", []):
                prompt_text = prompt_item.get("prompt", "")
                if prompt_text:
                    output = self.infer(prompt_text, model)
                    output = self._postprocess_output(prompt_item, output)
                    outputs.append(output)
            
            # Save results
            json_content[output_key] = outputs
            write_json(prompt_file, json_content)
            
            # Generate human-readable refined file
            self._generate_refined_file(prompt_file, json_content, model, outputs)
        
        # Store inference timing and token usage
        inference_elapsed = time.time() - inference_start
        self._logger.info(f"Total inference time: {inference_elapsed:.2f}s, tokens: {self._inference_tokens}")
        
        # Store in project metadata
        self.project._inference_time = inference_elapsed
        self.project._inference_tokens = self._inference_tokens
        
        return []

    def _postprocess_output(self, prompt_item: Dict[str, Any], output: str) -> str:
        """Post-process LLM output, handle fallback synthesis for insertion mode."""
        if not prompt_item.get("is_insert_only"):
            return output

        cleaned = (output or "").replace("<add here>\n", "").replace("<add here>", "")

        parsed = self._parse_insert_output(cleaned)
        if parsed is not None:
            insert_lines, anchor = parsed
            if not insert_lines:
                insert_lines = prompt_item.get("insert_patch_lines", [])
            if not anchor:
                anchor = prompt_item.get("anchor_code", "")
            return self._compose_insert_text(insert_lines, anchor)

        insert_lines = prompt_item.get("insert_patch_lines", [])
        if insert_lines and any(line.strip() in cleaned for line in insert_lines):
            return cleaned

        return self._compose_insert_text(insert_lines, prompt_item.get("anchor_code", ""))

    def _parse_insert_output(self, text: str) -> Optional[tuple[List[str], str]]:
        """Parse structured insertion output. Returns (insert_lines, anchor_text) or None."""
        lines = text.splitlines()
        state = None
        insert_lines: List[str] = []
        anchor_lines: List[str] = []

        for line in lines:
            if line.strip() == "INSERT_BEFORE:":
                state = "insert"
                continue
            if line.strip() == "ANCHOR:":
                state = "anchor"
                continue
            if state == "insert":
                insert_lines.append(line)
            elif state == "anchor":
                anchor_lines.append(line)

        if state is None and not insert_lines and not anchor_lines:
            return None

        return insert_lines, "\n".join(anchor_lines)

    def _compose_insert_text(self, insert_lines: List[str], anchor: str) -> str:
        """Synthesize insertion result: new lines + original anchor."""
        insert_part = "\n".join(insert_lines).strip("\n")
        anchor_part = (anchor or "").strip("\n")

        if insert_part and anchor_part:
            return insert_part + "\n" + anchor_part
        if insert_part:
            return insert_part
        return anchor_part
    
    def _generate_refined_file(
        self, 
        prompt_file: Path, 
        json_content: Dict, 
        model: str, 
        outputs: List[str]
    ) -> None:
        """
        Generate readable prompt-refined file
        
        Contains complete prompt and LLM output for manual inspection
        """
        # Generate refined file name: {prompt_name}[-{model}]-refined.txt
        prompt_stem = prompt_file.stem
        if f"-{model}" not in prompt_stem and model != "deepseek-api":
            refined_file = prompt_file.parent / f"{prompt_stem}-{model}-refined.txt"
        else:
            refined_file = prompt_file.parent / f"{prompt_stem}-refined.txt"
        
        try:
            with open(refined_file, 'w', encoding='utf-8') as f:
                # File header
                f.write("=" * 80 + "\n")
                f.write("LLM Inference Result - Refined View\n")
                f.write("=" * 80 + "\n\n")
                
                # Metadata
                f.write("📋 Metadata\n")
                f.write("-" * 80 + "\n")
                f.write(f"Project ID:     {json_content.get('project_id', 'N/A')}\n")
                f.write(f"Package Name:   {json_content.get('package_name', 'N/A')}\n")
                f.write(f"Version:        {json_content.get('version', 'N/A')}\n")
                f.write(f"Model:          {model}\n")
                f.write(f"Prompt File:    {prompt_file.name}\n")
                f.write(f"Customization:  {json_content.get('customization', 'N/A')}\n")
                f.write(f"Method:         {json_content.get('localization_method', 'N/A')}\n")
                f.write(f"Patch Commit:   {json_content.get('patch_commit', 'N/A')}\n")
                f.write(f"Target Commit:  {json_content.get('target_commit', 'N/A')}\n")
                f.write("\n")
                
 # process prompt output
                prompts = json_content.get("prompt", [])
                for idx, (prompt_item, output) in enumerate(zip(prompts, outputs), 1):
                    f.write("=" * 80 + "\n")
                    f.write(f"Prompt #{idx}\n")
                    f.write("=" * 80 + "\n\n")
                    
                    # Prompt content
                    f.write("📝 Input Prompt\n")
                    f.write("-" * 80 + "\n")
                    prompt_text = prompt_item.get("prompt", "")
                    f.write(prompt_text)
                    f.write("\n\n")
                    
                    # Localization information(if available)
                    if "localization" in prompt_item:
                        f.write("🎯 Localization Info\n")
                        f.write("-" * 80 + "\n")
                        loc_info = prompt_item["localization"]
                        f.write(f"File: {loc_info.get('file', 'N/A')}\n")
                        f.write(f"Lines: {loc_info.get('lines', 'N/A')}\n")
                        if "code" in loc_info:
                            f.write(f"Code:\n{loc_info['code']}\n")
                        f.write("\n")
                    
                    # LLM output
                    f.write("🤖 LLM Output\n")
                    f.write("-" * 80 + "\n")
                    f.write(output)
                    f.write("\n\n")
                    
                    # statisticsinformation
                    f.write("📊 Statistics\n")
                    f.write("-" * 80 + "\n")
                    f.write(f"Prompt Length: {len(prompt_text)} characters\n")
                    f.write(f"Output Length: {len(output)} characters\n")
                    f.write("\n\n")
                
 # 
                f.write("=" * 80 + "\n")
                f.write("End of Refined View\n")
                f.write("=" * 80 + "\n")
            
            logger.info(f"Generated refined file: {refined_file.name}")
            
        except Exception as e:
            logger.error(f"Failed to generate refined file for {prompt_file}: {e}")
    
    # =========================================================================
    # Cost Tracking
    # =========================================================================
    
    def _track_cost(self, model: str, tokens: int) -> None:
        """Track token usage for cost estimation."""
        cost_file = Path("./cost") / f"{model.replace('/', '-')}.txt"
        cost_file.parent.mkdir(exist_ok=True)
        
        with open(cost_file, "a") as f:
            print(tokens, file=f)
        
        if model not in self._cost_tracking:
            self._cost_tracking[model] = 0
        self._cost_tracking[model] += tokens
    
    def get_cost_summary(self) -> Dict[str, int]:
        """Get summary of token usage by model."""
        return self._cost_tracking.copy()


# =========================================================================
# Standalone Functions (for backward compatibility)
# =========================================================================

def LLM_infer(content: str, model: str) -> str:
    """
    Standalone function for LLM inference.
    
    This function is provided for backward compatibility and cases
    where a Project instance is not available.
    """
    if model == "deepseek-api":
        return deepseek_api(content)
    elif model == "gpt4o":
        return gpt4o(content)
    elif model == "gemini":
        return gemini(content)
    else:
        raise LLMInferenceError(
            f"Unknown model: {model}. Only API models are supported.",
            model=model,
        )


def deepseek_api(content: str) -> str:
    """Query DeepSeek API."""
    try:
        from openai import OpenAI
        
        client = OpenAI(
            api_key=config.llm.deepseek_api_key,
            base_url=config.llm.deepseek_base_url,
        )
        
        response = client.chat.completions.create(
            model=config.llm.deepseek_model,
            messages=[
                {"role": "user", "content": content},
            ],
            stream=False,
            temperature=0,
            extra_body={"enable_thinking": False},  # Disable thinking for non-streaming calls
        )
        
        return response.choices[0].message.content or ""
    except Exception as e:
        logger.error(f"DeepSeek API error: {e}")
        return ""


def gpt4o(content: str) -> str:
    """Query GPT-4 API."""
    try:
        from openai import OpenAI
        
        client = OpenAI(
            api_key=config.llm.openai_api_key,
            base_url=config.llm.openai_base_url,
        )
        
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "user", "content": content},
            ],
            stream=False,
            temperature=0,
        )
        
        return response.choices[0].message.content or ""
    except Exception as e:
        logger.error(f"GPT-4 API error: {e}")
        return ""


def gemini(content: str, max_retries: int = 10) -> str:
    """Query Gemini API with retry logic."""
    try:
        from openai import OpenAI
        import openai
        
        client = OpenAI(
            api_key=config.llm.openai_api_key,
            base_url=config.llm.openai_base_url,
        )
        
        for attempt in range(max_retries):
            try:
                response = client.chat.completions.create(
                    model="gemini-2.5-flash",
                    messages=[
                        {"role": "user", "content": content},
                    ],
                    stream=False,
                    temperature=0,
                )
                return response.choices[0].message.content or ""
            except openai.InternalServerError:
                logger.warning(f"Gemini retry {attempt + 1}/{max_retries}")
                time.sleep(2 ** attempt)
        
        raise APIRequestFailedError(
            f"Gemini request failed after {max_retries} retries"
        )
    except Exception as e:
        logger.error(f"Gemini API error: {e}")
        return ""
