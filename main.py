from concurrent.futures import ThreadPoolExecutor
from typing import Optional, Tuple
from pathlib import Path
from patch_processor import PatchProcessor, PatchInfo
from rule_manager import RuleManager
from llm_client import LLMClient
from git_manager import GitManager
from config import Config
from rule_validator import RuleValidator
import argparse
import logging
import os
import json
import csv
from datetime import datetime

class AutoGrep:
    def __init__(self, config: Config):
        self.config = config
        self.rule_manager = RuleManager(config)
        self.patch_processor = PatchProcessor(config)
        self.llm_client = LLMClient(config)
        self.git_manager = GitManager(config)
        self.rule_validator = RuleValidator(config)
        
        # Initialize CSV logging if enabled
        if self.config.log_rules_csv:
            self.csv_file = Path("stats/generated_rules_log.csv")
            self._init_csv_log()
            logging.info("CSV logging enabled - successful rule generations will be logged to stats/generated_rules_log.csv")
        else:
            self.csv_file = None
            logging.info("CSV logging disabled - use --log-rules-csv to enable rule generation tracking")
        
    def _init_csv_log(self):
        """Initialize CSV log file with headers if it doesn't exist."""
        # Create stats directory if it doesn't exist
        self.csv_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Create CSV file with headers if it doesn't exist
        if not self.csv_file.exists():
            with open(self.csv_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'timestamp', 
                    'patch_file', 
                    'rule_id', 
                    'rule_filename', 
                    'language'
                ])
            logging.info(f"Created CSV log file: {self.csv_file}")
    
    def _log_successful_rule_generation(self, patch_file: Path, rule: dict, language: str):
        """Log successful rule generation to CSV file."""
        # Only log if CSV logging is enabled
        if not self.config.log_rules_csv or not self.csv_file:
            return
            
        try:
            rule_filename = f"{language}/{rule['id']}.yml"
            timestamp = datetime.now().isoformat()
            
            with open(self.csv_file, 'a', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow([
                    timestamp,
                    patch_file.name,
                    rule['id'],
                    rule_filename,
                    language
                ])
            logging.debug(f"Logged successful rule generation to CSV: {patch_file.name} -> {rule_filename}")
        except Exception as e:
            logging.error(f"Failed to log rule generation to CSV: {e}")
        
    def process_patch(self, patch_file: Path) -> Optional[Tuple[dict, PatchInfo]]:
        """Process a single patch file with improved rule checking."""
        # Check if patch has already been processed
        if self.config.cache_manager.is_patch_processed(patch_file.name):
            logging.info(f"Skipping already processed patch: {patch_file.name}")
            return None
            
        try:
            patch_info = self.patch_processor.process_patch(patch_file)
            if not patch_info:
                self.config.cache_manager.mark_patch_processed(patch_file.name)
                logging.warning(f"Failed to process patch file: {patch_file}")
                return None
                
            # Check if repo is known to fail
            repo_key = f"{patch_info.repo_owner}/{patch_info.repo_name}"
            if self.config.cache_manager.is_repo_failed(repo_key):
                error = self.config.cache_manager.get_repo_error(repo_key)
                logging.warning(f"Skipping known failed repository {repo_key}: {error}")
                self.config.cache_manager.mark_patch_processed(patch_file.name)
                return None
                
            # Prepare repository
            repo_path = self.git_manager.prepare_repo(patch_info)
            if not repo_path:
                self.config.cache_manager.mark_repo_failed(repo_key, "Failed to prepare repository")
                self.config.cache_manager.mark_patch_processed(patch_file.name)
                return None
            
            # Get the language from patch info
            language = patch_info.file_changes[0].language
            
            # Check if any existing rules can detect this vulnerability
            existing_rules = self.rule_manager.rules.get(language, [])
            is_detected, detecting_rule = self.rule_validator.check_existing_rules(
                patch_info, repo_path, existing_rules
            )
            
            if is_detected:
                logging.info(f"Vulnerability already detectable by existing rule: {detecting_rule}")
                self.config.cache_manager.mark_patch_processed(patch_file.name)
                return None
                
            # Initialize error tracking
            error_msg = None
            
            # Try generating and validating rule
            for attempt in range(self.config.max_retries):
                logging.info(f"Attempt {attempt + 1}/{self.config.max_retries} for patch {patch_file}")
                
                rule = self.llm_client.generate_rule(patch_info, error_msg)
                if not rule:
                    error_msg = "Failed to generate valid rule structure"
                    continue
                
                is_valid, validation_error = self.rule_validator.validate_rule(
                    rule, patch_info, repo_path
                )
                
                if is_valid:
                    logging.info(f"Successfully generated valid rule for {patch_file}")
                    self.config.cache_manager.mark_patch_processed(patch_file.name)
                    return (rule, patch_info)
                    
                # If validation failed due to parse errors, skip this patch
                if validation_error and ("Parse error" in validation_error or 
                                    "Syntax error" in validation_error or
                                    "Skipped all files" in validation_error):
                    logging.info(f"Skipping patch due to parse errors: {validation_error}")
                    self.config.cache_manager.mark_patch_processed(patch_file.name)
                    return None
                    
                # Otherwise, use the error message for the next attempt
                error_msg = validation_error
                logging.warning(f"Attempt {attempt + 1} failed: {error_msg}")
            
            self.config.cache_manager.mark_patch_processed(patch_file.name)
            return None
            
        except Exception as e:
            logging.error(f"Unexpected error processing patch {patch_file}: {e}", exc_info=True)
            self.config.cache_manager.mark_patch_processed(patch_file.name)
            return None
        finally:
            # Always reset the repository state if it exists
            if repo_path and repo_path.exists():
                if not self.git_manager.reset_repo(repo_path):
                    logging.warning(f"Failed to reset repository state for: {repo_path}")
                    # If reset fails, we might want to force cleanup
                    self.git_manager.cleanup_repo(repo_path)

    def _process_repo_patches(self, patches: list) -> list:
        """Process all patches for a single repository with caching."""
        rules = []
        for patch_file in patches:
            try:
                result = self.process_patch(patch_file)
                if result:  # Check if we got a valid result
                    rule, patch_info = result  # Properly unpack the tuple
                    if rule and patch_info and patch_info.file_changes:
                        language = patch_info.file_changes[0].language
                        # Store the rule immediately after generation
                        self.rule_manager.add_generated_rule(language, rule)
                        # Log the successful rule generation to CSV
                        self._log_successful_rule_generation(patch_file, rule, language)
                        rules.append(rule)
                        logging.info(f"Successfully stored rule for {patch_file} in {language}")
            except Exception as e:
                logging.error(f"Error processing patch {patch_file}: {e}", exc_info=True)
        return rules

    def run(self):
        """Main execution flow with caching."""
        # Load initial rules
        self.rule_manager.load_initial_rules()
        
        # Get all patch files
        patch_files = list(self.config.patches_dir.glob("*.patch"))
        
        # Group patches by repository
        repo_patches = {}
        for patch_file in patch_files:
            # Skip if already processed
            if self.config.cache_manager.is_patch_processed(patch_file.name):
                logging.info(f"Skipping already processed patch: {patch_file.name}")
                continue
                
            try:
                # Try to parse the patch filename to get repo info
                repo_owner, repo_name, _ = self.patch_processor.parse_patch_filename(patch_file.name)
                repo_key = f"{repo_owner}/{repo_name}"
                
                # Skip if repo is known to fail
                if self.config.cache_manager.is_repo_failed(repo_key):
                    error = self.config.cache_manager.get_repo_error(repo_key)
                    logging.warning(f"Skipping known failed repository {repo_key}: {error}")
                    self.config.cache_manager.mark_patch_processed(patch_file.name)
                    continue
                    
                if repo_key not in repo_patches:
                    repo_patches[repo_key] = []
                repo_patches[repo_key].append(patch_file)
            except ValueError as e:
                logging.error(f"Error parsing patch filename {patch_file}: {e}")
                self.config.cache_manager.mark_patch_processed(patch_file.name)
                continue
        
        # Process different repos in parallel with max 4 workers
        with ThreadPoolExecutor(max_workers=2) as executor:
            repo_futures = []
            for repo_key, patches in repo_patches.items():
                future = executor.submit(self._process_repo_patches, patches)
                repo_futures.append(future)
            
            # Wait for all repos to complete
            for future in repo_futures:
                try:
                    rules = future.result()
                    # Rules are already stored in _process_repo_patches, just collect results
                    logging.info(f"Completed processing batch with {len(rules) if rules else 0} rules")
                except Exception as e:
                    logging.error(f"Error processing repository patches: {e}")

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="AutoGrep: Automated Semgrep rule generation from vulnerability patches"
    )
    
    parser.add_argument(
        "--patches-dir",
        type=Path,
        default=Path("cvedataset-patches"),
        help="Directory containing vulnerability patches"
    )
    
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("generated_rules"),
        help="Directory for generated rules"
    )
    
    parser.add_argument(
        "--repos-cache-dir",
        type=Path,
        default=Path("cache/repos"),
        help="Directory for cached repositories"
    )
    
    parser.add_argument(
        "--max-files-changed",
        type=int,
        default=1,
        help="Maximum number of files changed in patch"
    )
    
    parser.add_argument(
        "--max-retries",
        type=int,
        default=3,
        help="Maximum number of LLM generation attempts"
    )
    
    parser.add_argument(
        "--openrouter-api-key",
        default=os.environ.get("OPENROUTER_API_KEY"),
        help="OpenRouter API key (can also be set via OPENROUTER_API_KEY env var)"
    )
    
    parser.add_argument(
        "--openrouter-base-url",
        default="https://openrouter.ai/api/v1",
        help="OpenRouter API base URL"
    )
    
    parser.add_argument(
        "--generation-model",
        default="deepseek/deepseek-chat",
        help="LLM model for rule generation"
    )
    
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging level"
    )
    
    parser.add_argument(
        "--log-rules-csv",
        action="store_true",
        help="Enable CSV logging of successfully generated rules to stats/generated_rules_log.csv"
    )
    
    args = parser.parse_args()
    
    if not args.openrouter_api_key:
        parser.error("OpenRouter API key must be provided via --openrouter-api-key or OPENROUTER_API_KEY env var")
    
    return args

def main():
    """Main entry point."""
    args = parse_args()
    
    # Setup logging
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Initialize config
    config = Config(
        patches_dir=args.patches_dir,
        generated_rules_dir=args.output_dir,
        repos_cache_dir=args.repos_cache_dir,
        max_files_changed=args.max_files_changed,
        max_retries=args.max_retries,
        openrouter_api_key=args.openrouter_api_key,
        openrouter_base_url=args.openrouter_base_url,
        generation_model=args.generation_model,
        log_rules_csv=args.log_rules_csv
    )
    
    # Create necessary directories
    config.generated_rules_dir.mkdir(parents=True, exist_ok=True)
    config.repos_cache_dir.mkdir(parents=True, exist_ok=True)
    
    # Run AutoGrep
    try:
        autogen = AutoGrep(config)
        autogen.run()
    except Exception as e:
        logging.error(f"Error running AutoGrep: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())