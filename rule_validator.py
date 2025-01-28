import subprocess
from pathlib import Path
import json
import tempfile
from patch_processor import PatchInfo
from config import Config
import yaml
import git
from typing import Optional, Tuple, List
import logging

class RuleValidator:
    def __init__(self, config: Config):
        self.config = config

    def check_existing_rules(self, patch_info: PatchInfo, repo_path: Path, existing_rules: List[dict]) -> Tuple[bool, Optional[str]]:
        """
        Check if any existing rules can already detect the vulnerability.
        
        Args:
            patch_info: Information about the patch
            repo_path: Path to the repository
            existing_rules: List of existing rules for the same language
            
        Returns:
            Tuple[bool, Optional[str]]: 
                - Boolean indicating if vulnerability is already detectable
                - ID of the matching rule if found, None otherwise
        """
        try:
            repo = git.Repo(repo_path)
            
            # Check vulnerable version first
            parent_commit = repo.commit(patch_info.commit_id).parents[0]
            repo.git.checkout(parent_commit)
            
            # Create temporary rule file with all existing rules
            with tempfile.NamedTemporaryFile('w', suffix='.yml', delete=False) as tf:
                yaml.dump({"rules": existing_rules}, tf)
                rule_file = tf.name
            
            try:
                # Test vulnerable version
                vuln_results = []
                for file_change in patch_info.file_changes:
                    target_file = repo_path / file_change.file_path
                    if not target_file.exists():
                        continue
                        
                    results, error = self._run_semgrep(rule_file, str(target_file))
                    if error:
                        continue
                    vuln_results.extend(results)
                
                # If no rules detect the vulnerable version, we need a new rule
                if not vuln_results:
                    return False, None
                
                # Check fixed version
                repo.git.checkout(patch_info.commit_id)
                fixed_results = []
                
                for file_change in patch_info.file_changes:
                    target_file = repo_path / file_change.file_path
                    if not target_file.exists():
                        continue
                        
                    results, error = self._run_semgrep(rule_file, str(target_file))
                    if error:
                        continue
                    fixed_results.extend(results)
                
                # If any rule detects vulnerability in vulnerable version but not in fixed version,
                # we don't need a new rule
                detecting_rules = set()
                for result in vuln_results:
                    rule_id = result.get('check_id')
                    if rule_id and not any(r.get('check_id') == rule_id for r in fixed_results):
                        detecting_rules.add(rule_id)
                
                if detecting_rules:
                    return True, next(iter(detecting_rules))  # Return first detecting rule ID
                
                return False, None
                
            finally:
                # Clean up temporary rule file
                try:
                    Path(rule_file).unlink()
                except Exception as e:
                    logging.warning(f"Failed to delete temporary rule file: {e}")
                    
        except Exception as e:
            logging.error(f"Error checking existing rules: {e}", exc_info=True)
            return False, None
        
    def _run_semgrep(self, rule_file: str, target_path: str) -> Tuple[list, Optional[str]]:
        """Run semgrep with better error classification."""
        try:
            result = subprocess.run(
                ["semgrep", "--config", rule_file, "--json", target_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Try to parse JSON output regardless of return code
            try:
                if result.stdout:
                    output = json.loads(result.stdout)
                    results = output.get("results", [])
                    errors = output.get("errors", [])
                    
                    # Process errors if any
                    if errors:
                        for error in errors:
                            # Skip if it's a parsing error for the target file
                            if isinstance(error, dict):
                                error_type = error.get('type', '')
                                if any(t in error_type for t in ['ParseError', 'SyntaxError', 'TokenError']):
                                    logging.warning(f"Skipping file due to parse error: {error.get('long_msg', '')}")
                                    return [], None  # Return None to indicate skip
                                
                                # For rule-related errors, return the error message
                                if 'InvalidRuleSchemaError' in error_type or 'InvalidRuleError' in error_type:
                                    return [], error.get('long_msg', str(error))
                    
                    return results, None
                    
                return [], None  # No output but no error either
                
            except json.JSONDecodeError:
                if "Parse error" in result.stderr or "Syntax error" in result.stderr:
                    logging.warning(f"Skipping file due to parse error: {result.stderr}")
                    return [], None
                return [], f"Failed to parse semgrep output: {result.stderr}"
                
        except subprocess.TimeoutExpired:
            return [], "Semgrep process timed out"
        except Exception as e:
            return [], f"Error running semgrep: {str(e)}"

    def validate_rule(self, rule: dict, patch_info: PatchInfo, repo_path: Path) -> Tuple[bool, Optional[str]]:
        """Validate a generated rule using semgrep with improved error handling."""
        rule_file = None
        try:
            with tempfile.NamedTemporaryFile('w', suffix='.yml', delete=False) as tf:
                yaml.dump({"rules": [rule]}, tf)
                rule_file = tf.name
            
            repo = git.Repo(repo_path)
            
            # Check vulnerable version
            parent_commit = repo.commit(patch_info.commit_id).parents[0]
            repo.git.checkout(parent_commit)
            
            # Test all files in vulnerable version
            vuln_results = []
            skip_count = 0
            for file_change in patch_info.file_changes:
                target_file = repo_path / file_change.file_path
                if not target_file.exists():
                    return False, f"Target file not found: {file_change.file_path}"
                
                results, error = self._run_semgrep(rule_file, str(target_file))
                if error:
                    # If it's a rule error, propagate it up
                    return False, error
                elif results is None:
                    # Skip this file but continue with others
                    skip_count += 1
                    continue
                vuln_results.extend(results)
            
            # If all files were skipped, skip this patch
            if skip_count == len(patch_info.file_changes):
                return False, "Skipped all files due to parsing errors"
            
            # Check fixed version
            repo.git.checkout(patch_info.commit_id)
            
            # Test all files in fixed version
            fixed_results = []
            for file_change in patch_info.file_changes:
                target_file = repo_path / file_change.file_path
                if not target_file.exists():
                    return False, f"Target file not found after checkout: {file_change.file_path}"
                
                results, error = self._run_semgrep(rule_file, str(target_file))
                if error:
                    return False, error
                elif results is None:
                    continue  # Skip this file
                fixed_results.extend(results)
            
            # Rule is valid if it detects vulnerability in parent commit but not in fixed commit
            is_valid = len(vuln_results) > 0 and len(fixed_results) == 0
            
            if not is_valid:
                if len(vuln_results) == 0:
                    error_msg = "Rule failed to detect vulnerability in original version"
                elif len(fixed_results) > 0:
                    error_msg = "Rule incorrectly detected vulnerability in fixed version"
                else:
                    error_msg = "Rule validation failed for unknown reason"
                return False, error_msg
                
            return True, None
            
        except git.exc.GitCommandError as e:
            return False, f"Git error during validation: {str(e)}"
        except Exception as e:
            return False, f"Validation error: {str(e)}"
        finally:
            if rule_file:
                try:
                    Path(rule_file).unlink()
                except Exception as e:
                    logging.warning(f"Failed to delete temporary rule file: {e}")