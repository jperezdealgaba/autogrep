import yaml
from pathlib import Path
from typing import List, Dict
from config import Config
import logging

class RuleManager:
    def __init__(self, config: Config):
        self.config = config
        self.rules: Dict[str, List[dict]] = {}  # language -> rules
        
    def load_initial_rules(self):
        """Load all existing Semgrep rules from the rules directory."""
        for rule_file in self.config.rules_dir.rglob("*.yml"):
            language = rule_file.parent.parent.name
            try:
                with open(rule_file) as f:
                    rules = yaml.safe_load(f)
                if language not in self.rules:
                    self.rules[language] = []
                self.rules[language].extend(rules.get("rules", []))
            except Exception as e:
                logging.error(f"Error loading rule file {rule_file}: {e}")

    def add_generated_rule(self, language: str, rule: dict):
        """Add a new generated rule and save it to the generated_rules directory."""
        if language not in self.rules:
            self.rules[language] = []
        
        # Check if rule already exists
        if any(existing['id'] == rule['id'] for existing in self.rules[language]):
            logging.warning(f"Rule with ID {rule['id']} already exists for language {language}")
            return
        
        self.rules[language].append(rule)
        
        # Save to generated_rules directory
        output_dir = self.config.generated_rules_dir / language
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Use rule ID in filename for better traceability
        output_file = output_dir / f"{rule['id']}.yml"
        
        try:
            with open(output_file, 'w') as f:
                yaml.dump({"rules": [rule]}, f, sort_keys=False)
            logging.info(f"Successfully saved rule {rule['id']} to {output_file}")
        except Exception as e:
            logging.error(f"Error saving rule {rule['id']} to {output_file}: {e}")