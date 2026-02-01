#!/usr/bin/env python3
"""
SCA-Repair CLI Tool

Features:
1. Run all projects in batch (from target-project.txt)
2. Run a single project
3. Run a single stage
4. Flexible model and method configuration

Usage Examples:
    # Run all projects in batch
    python run.py --all

    # Run a single project
    python run.py --project /path/to/project
    
    # Run only localization stage
    python run.py --project <path> --stage localize
    
    # Use a specific model
    python run.py --all --model gpt4o
    
    # Run only localization and generation stages
    python run.py --project <path> --stages localize generate
"""

import sys
import argparse
import logging
from pathlib import Path
from typing import List, Optional

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Pre-check --debug argument and configure logging (must be before importing other modules)
if '--debug' in sys.argv:
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
else:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

# Disable verbose logging from third-party libraries
logging.getLogger('httpx').setLevel(logging.WARNING)
logging.getLogger('httpcore').setLevel(logging.WARNING)
logging.getLogger('openai').setLevel(logging.INFO)

from core import Pipeline, Config
from core.pipeline import (
    whole_process,
    localize,
    generate_prompts,
    run_inference,
    run_tests,
    analyze_results,
)
from core.utils.file import read_lines

logger = logging.getLogger(__name__)


class CLIRunner:
    """CLI Runner"""
    
    def __init__(self, config: Config):
        self.config = config
        self.pipeline = Pipeline()
    
    def run_all_projects(
        self,
        model: str = "deepseek-api",
        stages: Optional[List[str]] = None,
        method: str = "history_llm",
        context_granularity: Optional[str] = None,
        use_oracle: bool = False,
    ) -> None:
        """
        Run all projects
        
        Args:
            model: Model to use
            stages: List of stages to run
            method: Localization method
            context_granularity: Context granularity
        """
        project_list_file = self.config.paths.project_list_file
        
        if not project_list_file.exists():
            logger.error(f"Project list file does not exist: {project_list_file}")
            return
        
        project_paths = self.pipeline.get_project_paths()
        total = len(project_paths)
        
        logger.info(f"Starting batch processing of {total} projects...")
        logger.info(f"Model: {model}")
        logger.info(f"Localization method: {'Oracle (localization.csv)' if use_oracle else method}")
        logger.info(f"Context granularity: {context_granularity or 'dynamic (auto)'}")
        logger.info(f"Stages: {stages or 'all'}")
        
        for idx, path in enumerate(project_paths, 1):
            logger.info(f"\n[{idx}/{total}] Processing project: {path.name}")
            try:
                result = self.pipeline.run_single(
                    project_path=path,
                    model=model,
                    stages=stages,
                    localization_method='oracle' if use_oracle else method,
                    context_granularity=context_granularity,
                )
                # Add result to pipeline results list
                self.pipeline._results.append(result)
                
                status = "SUCCESS" if result.success else "FAILED"
                logger.info(f"  {status} - Completed stages: {result.stages_completed}")
                if result.error:
                    logger.error(f"  Error: {result.error}")
            except Exception as e:
                logger.error(f"  Processing failed: {e}")
        
        # Print summary
        self.pipeline.print_summary()
    
    def run_single_project(
        self,
        project_path: Path,
        model: str = "deepseek-api",
        stages: Optional[List[str]] = None,
        method: str = "history_llm",
        context_granularity: Optional[str] = None,
        use_oracle: bool = False,
    ) -> None:
        """
        Run a single project
        
        Args:
            project_path: Project path
            model: Model to use
            stages: List of stages to run
            method: Localization method
            context_granularity: Context granularity
        """
        logger.info(f"Processing single project: {project_path}")
        logger.info(f"Model: {model}")
        logger.info(f"Localization method: {'Oracle (localization.csv)' if use_oracle else method}")
        logger.info(f"Context granularity: {context_granularity or 'dynamic (auto)'}")
        logger.info(f"Stages: {stages or 'all'}")
        
        try:
            result = self.pipeline.run_single(
                project_path=project_path,
                model=model,
                stages=stages,
                localization_method='oracle' if use_oracle else method,
                context_granularity=context_granularity,
            )
            
            if result.success:
                logger.info(f"SUCCESS!")
                logger.info(f"Completed stages: {result.stages_completed}")
            else:
                logger.error(f"FAILED!")
                logger.error(f"Error: {result.error}")
            
        except Exception as e:
            logger.error(f"Execution failed: {e}")
            raise
    
    def run_single_stage(
        self,
        stage: str,
        project_path: Optional[Path] = None,
        model: str = "deepseek-api",
        method: Optional[str] = None,
    ) -> None:
        """
        Run a single stage
        
        Args:
            stage: Stage name (localize/generate/infer/test/analyze)
            project_path: Project path (None to process all projects)
            model: Model to use
            method: Localization method (only for localize stage)
        """
        logger.info(f"Running single stage: {stage}")
        if project_path:
            logger.info(f"Project: {project_path}")
        else:
            logger.info(f"Processing all projects")
        logger.info(f"Model: {model}")
        
        try:
            if stage == "localize":
                method = method or "line"
                logger.info(f"Localization method: {method}")
                localize(model=model, method=method, path=project_path)
            elif stage == "generate":
                generate_prompts(model=model, path=project_path)
            elif stage == "infer":
                run_inference(model=model, path=project_path)
            elif stage == "test":
                run_tests(model=model, path=project_path)
            elif stage == "analyze":
                analyze_results(model=model, path=project_path)
            else:
                logger.error(f"Unknown stage: {stage}")
                return
            
            logger.info(f"Stage '{stage}' completed!")
            
        except Exception as e:
            logger.error(f"Stage '{stage}' execution failed: {e}")
            raise


def create_parser() -> argparse.ArgumentParser:
    """Create command line argument parser"""
    parser = argparse.ArgumentParser(
        description="SCA-Repair CLI Tool - Automated Security Patch Backporting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run all projects in batch (complete pipeline)
  python run.py --all
  
  # Run a single project
  python run.py --project /path/to/project
  
  # Run specific stages for a single project
  python run.py --project /path/to/project --stages localize generate
  
  # Run only localization stage (all projects)
  python run.py --stage localize
  
  # Use a specific model
  python run.py --all --model gpt4o
  
  # Use a specific localization method
  python run.py --project /path/to/project --stage localize --method function
  
  # Debug mode
  python run.py --project /path/to/project --debug
        """,
    )
    
    # Run mode
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "--all",
        action="store_true",
        help="Run all projects in batch (from target-project.txt)",
    )
    mode_group.add_argument(
        "--project",
        type=Path,
        metavar="PATH",
        help="Run a single project",
    )
    mode_group.add_argument(
        "--stage",
        type=str,
        choices=["localize", "generate", "infer", "test", "analyze"],
        help="Run only a single stage (can be used with --project)",
    )
    
    # Configuration arguments
    parser.add_argument(
        "--model",
        type=str,
        default="deepseek-api",
        help="LLM model to use (default: deepseek-api)",
    )
    
    parser.add_argument(
        "--stages",
        type=str,
        nargs="+",
        choices=["localize", "generate", "infer", "test"],
        help="List of stages to run (only for --all or --project)",
    )
    
    parser.add_argument(
        "--method",
        type=str,
        default="history_llm",
        choices=["line", "line_log", "function", "file", "history_llm", 
                 "history_similarity", "direct_llm", "direct_similarity"],
        help="Localization method (only for localize stage, default: history_llm)",
    )
    
    parser.add_argument(
        "--context-granularity",
        type=str,
        choices=["line", "structure", "function", "file"],
        help="Context granularity (line/structure/function/file), skip localization stage and use existing results",
    )
    
    parser.add_argument(
        "--oracle",
        action="store_true",
        help="Use Oracle localization (localization.csv), skip localization stage and use perfect localization",
    )
    
    # Other options
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode (verbose logging)",
    )
    
    parser.add_argument(
        "--parallel",
        action="store_true",
        help="Process projects in parallel (experimental)",
    )
    
    return parser


def main():
    """Main function"""
    parser = create_parser()
    args = parser.parse_args()
    
    # Logging already configured at module load, just confirm here
    if args.debug:
        logger.debug("Debug mode enabled")
    
    # Initialize configuration
    config = Config()
    
    # Validate configuration
    warnings = config.validate()
    if warnings:
        logger.warning("Configuration warnings:")
        for warning in warnings:
            logger.warning(f"  - {warning}")
    
    # Create runner
    runner = CLIRunner(config)
    
    try:
        # Batch process all projects
        if args.all:
            if args.parallel:
                logger.info("Using parallel mode...")
                runner.pipeline.run_parallel(
                    model=args.model,
                    stages=args.stages,
                    localization_method=args.method,
                    context_granularity=getattr(args, 'context_granularity', None),
                )
                runner.pipeline.print_summary()
            else:
                runner.run_all_projects(
                    model=args.model,
                    stages=args.stages,
                    method=args.method,
                    context_granularity=getattr(args, 'context_granularity', None),
                    use_oracle=args.oracle,
                )
        
        # Run single project
        elif args.project:
            if not args.project.exists():
                logger.error(f"Project path does not exist: {args.project}")
                sys.exit(1)

            if args.stage:
                # Single stage
                runner.run_single_stage(
                    stage=args.stage,
                    project_path=args.project,
                    model=args.model,
                    method=args.method,
                )
            else:
                # Complete pipeline or specified stages
                runner.run_single_project(
                    project_path=args.project,
                    model=args.model,
                    stages=args.stages,
                    context_granularity=getattr(args, 'context_granularity', None),
                    use_oracle=args.oracle,
                    method=args.method,
                )
        
        # Run single stage only (all projects)
        elif args.stage:
            runner.run_single_stage(
                stage=args.stage,
                project_path=None,
                model=args.model,
                method=args.method,
            )
        
        logger.info("\n" + "=" * 60)
        logger.info("Execution completed!")
        logger.info("=" * 60)
        
    except KeyboardInterrupt:
        logger.warning("\n\nUser interrupted execution")
        sys.exit(130)
    except Exception as e:
        logger.error(f"\nExecution failed: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
