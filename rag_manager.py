from pathlib import Path
from typing import Optional, List, Dict, Tuple
import yaml
import logging
import numpy as np
from sentence_transformers import SentenceTransformer
import torch
from dataclasses import dataclass
import subprocess
import re
from patch_processor import PatchInfo


@dataclass
class OpengrepRule:
    """Represents a rule from the opengrep-rules repository."""
    id: str
    content: dict  # Full rule content as dict
    yaml_text: str  # Full YAML representation
    language: str
    pattern: str
    message: str
    file_path: str  # Original file path in repo


class RagManager:
    """Manages RAG system for retrieving similar rules from opengrep-rules repository."""
    
    def __init__(self, 
                 repo_path: Optional[Path] = None,
                 top_k: int = 3,
                 auto_clone: bool = True,
                 embedding_model_name: str = 'all-MiniLM-L6-v2'):
        """
        Initialize RAG manager.
        
        Args:
            repo_path: Path to local opengrep-rules repository
            top_k: Default number of similar rules to retrieve
            auto_clone: Whether to auto-clone repository if not found
            embedding_model_name: Name of sentence-transformers model
        """
        self.top_k = top_k
        self.auto_clone = auto_clone
        self.repo_path = repo_path
        self.rules: List[OpengrepRule] = []
        self.embeddings: Dict[str, np.ndarray] = {}
        
        # Initialize embedding model
        logging.info(f"Loading embedding model: {embedding_model_name}")
        self.embedding_model = SentenceTransformer(embedding_model_name)
        if torch.cuda.is_available():
            self.embedding_model = self.embedding_model.to('cuda')
            logging.info("Using CUDA for embeddings")
        
        # Setup repository
        self._setup_repository()
        
        # Load rules and build embeddings
        if self.repo_path and self.repo_path.exists():
            self.load_opengrep_rules()
            self.build_embeddings()
            logging.info(f"RAG system initialized with {len(self.rules)} rules")
        else:
            logging.warning("RAG repository not available, RAG features disabled")
    
    def _setup_repository(self):
        """Setup opengrep-rules repository (clone if needed)."""
        if self.repo_path is None:
            # Use default cache location
            self.repo_path = Path("cache/opengrep-rules")
        
        # Check if repo exists
        if self.repo_path.exists() and (self.repo_path / ".git").exists():
            logging.info(f"Using existing opengrep-rules repository at: {self.repo_path}")
            return
        
        # Clone if auto_clone is enabled
        if self.auto_clone:
            logging.info(f"Cloning opengrep-rules repository to: {self.repo_path}")
            self._clone_repository()
        else:
            logging.warning(f"Repository not found at {self.repo_path} and auto-clone is disabled")
    
    def _clone_repository(self):
        """Clone opengrep-rules repository."""
        try:
            # Create parent directory
            self.repo_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Clone with shallow depth for efficiency
            cmd = [
                "git", "clone",
                "--depth", "1",
                "https://github.com/opengrep/opengrep-rules.git",
                str(self.repo_path)
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            logging.info(f"Successfully cloned opengrep-rules repository")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to clone repository: {e.stderr}")
            raise
        except Exception as e:
            logging.error(f"Error cloning repository: {e}")
            raise
    
    def load_opengrep_rules(self):
        """Load all rules from opengrep-rules repository."""
        if not self.repo_path or not self.repo_path.exists():
            logging.warning("Repository path not available")
            return
        
        logging.info(f"Loading rules from: {self.repo_path}")
        rules_loaded = 0
        
        # Find all YAML files recursively
        for yaml_file in self.repo_path.rglob("*.y*ml"):
            # Skip non-rule files
            if any(skip in str(yaml_file) for skip in ['.github', 'metadata', 'scripts', 'stats']):
                continue
            
            try:
                with open(yaml_file, 'r', encoding='utf-8') as f:
                    content = yaml.safe_load(f)
                
                # Skip if not a valid rule file
                if not content or 'rules' not in content:
                    continue
                
                # Extract each rule
                for rule in content['rules']:
                    if not isinstance(rule, dict):
                        continue
                    
                    # Extract required fields
                    rule_id = rule.get('id', f'unknown-{rules_loaded}')
                    pattern = rule.get('pattern', rule.get('patterns', ''))
                    message = rule.get('message', '')
                    languages = rule.get('languages', [])
                    
                    # Determine language (use first one if multiple)
                    language = languages[0] if languages else 'unknown'
                    
                    # Create full YAML text for this rule
                    yaml_text = yaml.dump({'rules': [rule]}, sort_keys=False, default_flow_style=False)
                    
                    # Create OpengrepRule object
                    opengrep_rule = OpengrepRule(
                        id=rule_id,
                        content=rule,
                        yaml_text=yaml_text,
                        language=language,
                        pattern=str(pattern),
                        message=message,
                        file_path=str(yaml_file.relative_to(self.repo_path))
                    )
                    
                    self.rules.append(opengrep_rule)
                    rules_loaded += 1
            
            except Exception as e:
                logging.debug(f"Error loading rule file {yaml_file}: {e}")
                continue
        
        logging.info(f"Loaded {rules_loaded} rules from opengrep-rules repository")
    
    def build_embeddings(self):
        """Build embeddings for all loaded rules."""
        if not self.rules:
            logging.warning("No rules loaded, skipping embedding generation")
            return
        
        logging.info(f"Building embeddings for {len(self.rules)} rules...")
        
        for rule in self.rules:
            # Create embedding from entire rule YAML
            embedding = self._get_embedding(rule.yaml_text)
            self.embeddings[rule.id] = embedding
        
        logging.info(f"Built {len(self.embeddings)} embeddings")
    
    def _get_embedding(self, text: str) -> np.ndarray:
        """Generate embedding for text."""
        try:
            with torch.no_grad():
                embedding = self.embedding_model.encode(text, convert_to_numpy=True)
            return embedding
        except Exception as e:
            logging.error(f"Error generating embedding: {e}")
            # Return zero vector as fallback
            embedding_dim = self.embedding_model.get_sentence_embedding_dimension()
            return np.zeros(embedding_dim)
    
    def build_query_from_patch(self, patch_info: PatchInfo) -> str:
        """
        Extract vulnerability keywords from patch to build query.
        
        Args:
            patch_info: Patch information
            
        Returns:
            Query string for similarity search
        """
        keywords = []
        
        # Add language
        language = patch_info.file_changes[0].language if patch_info.file_changes else 'unknown'
        keywords.append(language)
        
        # Common vulnerability keywords patterns
        vuln_patterns = [
            r'\b(sql|injection|xss|csrf|rce|xxe|ssrf|lfi|rfi)\b',
            r'\b(buffer\s+overflow|memory\s+leak|use\s+after\s+free)\b',
            r'\b(authentication|authorization|privilege|escalation)\b',
            r'\b(sanitize|validate|escape|encode|decode)\b',
            r'\b(deserialization|pickle|eval|exec)\b',
            r'\b(path\s+traversal|directory\s+traversal)\b',
            r'\b(command\s+injection|code\s+injection)\b',
            r'\b(insecure|unsafe|vulnerable|vulnerability|cve)\b',
            r'\b(crypto|encryption|cipher|hash|random)\b',
            r'\b(password|secret|token|key|credential)\b',
        ]
        
        # Extract from file changes (both the diff content and file paths)
        for file_change in patch_info.file_changes:
            changes_lower = file_change.changes.lower()
            
            # Look for vulnerability keywords in the diff
            for pattern in vuln_patterns:
                matches = re.findall(pattern, changes_lower)
                keywords.extend(matches)
            
            # Look for function definitions or calls in the diff
            func_patterns = [
                r'def\s+(\w+)',  # Python
                r'function\s+(\w+)',  # JavaScript
                r'public\s+\w+\s+(\w+)\s*\(',  # Java/C#
                r'fn\s+(\w+)',  # Rust
                r'func\s+(\w+)',  # Go
            ]
            
            for pattern in func_patterns:
                matches = re.findall(pattern, file_change.changes)
                keywords.extend([m for m in matches if len(m) > 3])  # Filter short names
            
            # Extract keywords from file path
            file_path_lower = file_change.file_path.lower()
            for pattern in vuln_patterns:
                matches = re.findall(pattern, file_path_lower)
                keywords.extend(matches)
        
        # Add generic security terms
        keywords.extend(['security', 'vulnerability'])
        
        # Remove duplicates and create query
        unique_keywords = list(dict.fromkeys(keywords))  # Preserve order
        query = ' '.join(unique_keywords[:15])  # Limit to 15 keywords
        
        logging.debug(f"Built query from patch: {query}")
        return query
    
    def retrieve_similar_rules(self, 
                               query: str, 
                               language: str, 
                               top_k: Optional[int] = None) -> List[OpengrepRule]:
        """
        Retrieve top-k similar rules based on query.
        
        Args:
            query: Search query string
            language: Target programming language
            top_k: Number of rules to retrieve (uses default if None)
            
        Returns:
            List of most similar OpengrepRule objects
        """
        if top_k is None:
            top_k = self.top_k
        
        if not self.rules or not self.embeddings:
            logging.warning("No rules or embeddings available for retrieval")
            return []
        
        # Filter rules by language first
        language_rules = [r for r in self.rules if r.language.lower() == language.lower()]
        
        if not language_rules:
            logging.warning(f"No rules found for language: {language}")
            # Fall back to all rules if no language match
            language_rules = self.rules
        
        logging.debug(f"Searching {len(language_rules)} {language} rules")
        
        # Generate query embedding
        query_embedding = self._get_embedding(query)
        
        # Calculate similarities
        similarities = []
        for rule in language_rules:
            if rule.id not in self.embeddings:
                continue
            
            rule_embedding = self.embeddings[rule.id]
            
            # Cosine similarity
            similarity = np.dot(query_embedding, rule_embedding) / (
                np.linalg.norm(query_embedding) * np.linalg.norm(rule_embedding)
            )
            
            similarities.append((rule, similarity))
        
        # Sort by similarity (descending)
        similarities.sort(key=lambda x: x[1], reverse=True)
        
        # Return top-k rules
        top_rules = [rule for rule, sim in similarities[:top_k]]
        
        logging.info(f"Retrieved {len(top_rules)} similar rules for query: {query[:50]}...")
        if top_rules:
            logging.debug(f"Top similarities: {[f'{sim:.3f}' for _, sim in similarities[:top_k]]}")
        
        return top_rules
    
    def format_rules_for_prompt(self, rules: List[OpengrepRule]) -> str:
        """
        Format retrieved rules for inclusion in LLM prompt.
        
        Args:
            rules: List of OpengrepRule objects
            
        Returns:
            Formatted string for prompt
        """
        if not rules:
            return ""
        
        formatted = []
        for i, rule in enumerate(rules, 1):
            formatted.append(f"Example {i}: {rule.id}")
            formatted.append("-" * 60)
            formatted.append(rule.yaml_text)
            formatted.append("")  # Empty line between rules
        
        return "\n".join(formatted)

