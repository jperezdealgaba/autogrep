from typing import Optional, Tuple
from config import Config
import logging
import yaml
from patch_processor import PatchInfo
import re
from openai import OpenAI
from pathlib import Path

class LLMClient:
    def __init__(self, config: Config):
        self.config = config
        self.client = OpenAI(
            api_key=config.openrouter_api_key,
            base_url=config.openrouter_base_url
        )
        
    def extract_response(self, text: str) -> str:
        """Remove thinking tags and markdown formatting from LLM response."""
        # Remove thinking tags
        text = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL)
        # Remove markdown code block markers
        text = re.sub(r'^```yaml\s*', '', text, flags=re.MULTILINE)
        text = re.sub(r'^```\s*$', '', text, flags=re.MULTILINE)
        # Remove any leading/trailing whitespace
        return text.strip()
    
    def clean_yaml_text(self, text: str) -> Optional[str]:
        """Clean and validate YAML text with better error handling."""
        if not text:
            return None
            
        # Remove any YAML document markers
        text = re.sub(r'^---\s*$', '', text, flags=re.MULTILINE)
        text = re.sub(r'^\.{3}\s*$', '', text, flags=re.MULTILINE)
        
        try:
            # First try to parse the YAML
            data = yaml.safe_load(text)
            
            # Ensure we have a valid rules structure
            if not isinstance(data, dict):
                data = {'rules': [data] if data else []}
            elif 'rules' not in data:
                data = {'rules': [data]}
                
            # Clean dump with proper formatting
            return yaml.dump(data, sort_keys=False, default_flow_style=False)
        except yaml.YAMLError as e:
            logging.error(f"YAML parsing error: {e}")
            # Try to salvage malformed YAML by wrapping in rules structure
            try:
                wrapped_text = f"rules:\n  - {text}"
                data = yaml.safe_load(wrapped_text)
                return yaml.dump(data, sort_keys=False, default_flow_style=False)
            except yaml.YAMLError:
                return None

    def validate_rule_schema(self, rule: dict) -> Tuple[bool, Optional[str]]:
        """Validate that the rule has all required fields."""
        required_fields = ['id', 'pattern', 'message', 'severity', 'languages']
        
        if not isinstance(rule, dict):
            return False, "Rule must be a dictionary"
            
        missing_fields = [field for field in required_fields if field not in rule]
        if missing_fields:
            return False, f"Missing required fields: {', '.join(missing_fields)}"
            
        # Validate severity
        valid_severities = ['ERROR', 'WARNING', 'INFO']
        if rule['severity'] not in valid_severities:
            return False, f"Invalid severity level. Must be one of: {', '.join(valid_severities)}"
            
        # Ensure id is properly formatted
        if not re.match(r'^[a-z0-9-]+$', rule['id']):
            return False, "Invalid id format. Must contain only lowercase letters, numbers, and hyphens"
            
        return True, None

    def _sanitize_rule(self, rule: dict, patch_info: PatchInfo) -> dict:
        """Ensure rule has all required fields and correct format."""
        if not isinstance(rule, dict):
            rule = {'rules': [rule]}
        
        # Extract the actual rule if wrapped in 'rules' list
        if 'rules' in rule and isinstance(rule['rules'], list):
            rule = rule['rules'][0]
        
        # Ensure rule has an ID
        if 'id' not in rule:
            # Generate an ID based on the repository and commit
            commit_short = patch_info.commit_id[:8]
            rule['id'] = f"vuln-{patch_info.repo_name.lower()}-{commit_short}"
        
        # Ensure rule has languages field
        if 'languages' not in rule:
            rule['languages'] = [patch_info.file_changes[0].language]
        
        # Ensure rule has severity
        if 'severity' not in rule:
            rule['severity'] = 'ERROR'
        
        # Ensure rule has metadata
        if 'metadata' not in rule:
            rule['metadata'] = {}
        
        metadata = rule['metadata']
        if 'source-url' not in metadata:
            metadata['source-url'] = f"github.com/{patch_info.repo_owner}/{patch_info.repo_name}/commit/{patch_info.commit_id}"
        
        if 'category' not in metadata:
            metadata['category'] = 'security'
        
        if 'technology' not in metadata:
            metadata['technology'] = [patch_info.file_changes[0].language]
        
        return rule

    def generate_rule(self, patch_info: PatchInfo, error_feedback: Optional[str] = None) -> Optional[dict]:
        """Generate a Semgrep rule using the LLM with improved validation."""
        prompt = self._build_prompt(patch_info, error_feedback)
        
        try:
            response = self.client.chat.completions.create(
                model="deepseek/deepseek-r1",
                messages=[
                    {"role": "system", "content": """You generate Semgrep rules in YAML format. 
    Return only the raw YAML content without any markdown formatting or additional text.
    Always include these required fields: id, pattern, message, severity, languages"""},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
            )
            
            if not response.choices:
                logging.error("No response generated from LLM")
                return None
            
            # Extract and clean the response
            content = response.choices[0].message.content
            if not content:
                logging.error("Empty response from LLM")
                return None
                
            rule_text = self.extract_response(content)
            if not rule_text:
                logging.error("No valid content after extracting response")
                return None
                
            rule_text = self.clean_yaml_text(rule_text)
            if not rule_text:
                logging.error("Failed to clean YAML text")
                return None
            
            try:
                rule_data = yaml.safe_load(rule_text)
                rule = self._sanitize_rule(rule_data, patch_info)
                
                # Validate the rule schema
                is_valid, error = self.validate_rule_schema(rule)
                if not is_valid:
                    logging.error(f"Invalid rule schema: {error}")
                    return None
                
                return rule
                
            except yaml.YAMLError as e:
                logging.error(f"Error parsing generated rule YAML: {e}")
                return None
                
        except Exception as e:
            logging.error(f"Error generating rule: {e}")
            return None
        
    def _build_prompt(self, patch_info: PatchInfo, error_feedback: Optional[str] = None) -> str:
        """Build prompt for rule generation with stronger emphasis on required fields."""
        all_changes = []
        for file_change in patch_info.file_changes:
            file_header = f"File: {file_change.file_path}\n"
            all_changes.append(file_header + file_change.changes)
        
        combined_changes = "\n\n".join(all_changes)
        
        language = patch_info.file_changes[0].language
        commit_short = patch_info.commit_id[:8]
        suggested_id = f"vuln-{patch_info.repo_name.lower()}-{commit_short}"
        
        prompt = f"""Generate a Semgrep rule to detect similar vulnerabilities in {language} code.

    Repository: github.com/{patch_info.repo_owner}/{patch_info.repo_name}
    Commit: {patch_info.commit_id}

    Changes:
    {combined_changes}

    CRITICAL: Your response must be a single YAML rule with ALL of these required fields:
    1. id: "{suggested_id}"
    2. pattern: The vulnerable code pattern
    3. languages: ["{language}"]
    4. message: Clear description of the vulnerability
    5. severity: One of [ERROR, WARNING, INFO]

    Optional fields that improve the rule:
    - pattern-not: Pattern that should not match (fixed version)
    - pattern-inside: Context pattern for where the rule should match
    - pattern-not-inside: Context pattern for where the rule should not match
    - metadata:
    source-url: github.com/{patch_info.repo_owner}/{patch_info.repo_name}/commit/{patch_info.commit_id}
    category: security
    technology: [{language}]

    Example format:
    rules:
    - id: "{suggested_id}"
        pattern: $VULNERABLE_PATTERN
        pattern-not: $FIXED_PATTERN
        languages: ["{language}"]
        message: "Clear description of the security issue"
        severity: ERROR
        metadata:
        source-url: github.com/{patch_info.repo_owner}/{patch_info.repo_name}/commit/{patch_info.commit_id}
        category: security
        technology:
            - {language}
    """

        if error_feedback:
            prompt += f"\nPrevious attempt failed with error: {error_feedback}\nFix these issues in your next attempt."
            
        return prompt

# And update the AutoGrep class's process_patch method to handle the error_msg correctly:

def process_patch(self, patch_file: Path) -> Optional[dict]:
    """Process a single patch file."""
    patch_info = self.patch_processor.process_patch(patch_file)
    if not patch_info:
        return None
        
    # Prepare repository
    repo_path = self.git_manager.prepare_repo(patch_info)
    if not repo_path:
        return None
        
    # Try generating and validating rule
    error_msg = None
    for attempt in range(self.config.max_retries):
        rule = self.llm_client.generate_rule(patch_info, error_msg)
        if not rule:
            error_msg = "Failed to generate valid YAML"
            continue
            
        is_valid, validation_error = self.rule_validator.validate_rule(rule, patch_info, repo_path)
        if is_valid:
            return rule
            
        error_msg = validation_error
        
    return None