from dataclasses import dataclass
from pathlib import Path
import re
from typing import Optional, Tuple, List
from config import Config
import logging

@dataclass
class FileChange:
    file_path: str
    changes: str
    language: str

@dataclass
class PatchInfo:
    repo_owner: str
    repo_name: str
    commit_id: str
    file_changes: List[FileChange]

class PatchProcessor:
    def __init__(self, config: Config):
        self.config = config
            
    def get_language_from_file(self, file_path: str) -> Optional[str]:
        """Determine programming language from file extension."""
        ext_map = {
            # Python
            ".py": "python",
            ".pyi": "python",
            ".pyx": "python",
            ".pyw": "python",
            
            # JavaScript/TypeScript
            ".js": "javascript",
            ".jsx": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".mjs": "javascript",
            ".cjs": "javascript",
            
            # Java
            ".java": "java",
            ".jav": "java",
            
            # C/C++
            ".cpp": "cpp",
            ".hpp": "cpp",
            ".cc": "cpp",
            ".cxx": "cpp",
            ".c++": "cpp",
            ".h": "cpp",
            ".hh": "cpp",
            ".hxx": "cpp",
            ".h++": "cpp",
            ".c": "c",
            
            # C#
            ".cs": "csharp",
            
            # Ruby
            ".rb": "ruby",
            ".rbw": "ruby",
            ".rake": "ruby",
            ".gemspec": "ruby",
            
            # PHP
            ".php": "php",
            ".phtml": "php",
            ".php3": "php",
            ".php4": "php",
            ".php5": "php",
            
            # Go
            ".go": "go",
            
            # Rust
            ".rs": "rust",
            
            # Swift
            ".swift": "swift",
            
            # Kotlin
            ".kt": "kotlin",
            ".kts": "kotlin",
            
            # Scala
            ".scala": "scala",
            ".sc": "scala",
            
            # HTML/CSS
            ".html": "html",
            ".htm": "html",
            ".xhtml": "html",
            ".css": "css",
            ".scss": "scss",
            ".sass": "sass",
            ".less": "less",
            
            # Shell scripting
            ".sh": "shell",
            ".bash": "shell",
            ".zsh": "shell",
            ".fish": "shell",
            
            # PowerShell
            ".ps1": "powershell",
            ".psm1": "powershell",
            ".psd1": "powershell",
            
            # Perl
            ".pl": "perl",
            ".pm": "perl",
            ".t": "perl",
            
            # R
            ".r": "r",
            ".R": "r",
            ".rmd": "r",
            
            # Lua
            ".lua": "lua",
            
            # Haskell
            ".hs": "haskell",
            ".lhs": "haskell",
            
            # Julia
            ".jl": "julia",
            
            # Dart
            ".dart": "dart",
            
            # Visual Basic
            ".vb": "vb",
            ".bas": "vb",
            ".vbs": "vb",
            
            # MATLAB
            ".m": "matlab",
            ".mat": "matlab",
            
            # Assembly
            ".asm": "assembly",
            ".s": "assembly",
            
            # SQL
            ".sql": "sql",
            
            # Markdown
            ".md": "markdown",
            ".markdown": "markdown",
            
            # XML
            ".xml": "xml",
            ".xsl": "xml",
            ".xsd": "xml",
            
            # JSON
            ".json": "json",
            
            # YAML
            ".yml": "yaml",
            ".yaml": "yaml",
            
            # Protocol Buffers
            ".proto": "protobuf",
            
            # Groovy
            ".groovy": "groovy",
            ".gvy": "groovy",
            
            # Objective-C
            ".m": "objectivec",
            ".mm": "objectivec",
            
            # F#
            ".fs": "fsharp",
            ".fsi": "fsharp",
            ".fsx": "fsharp",
            
            # Clojure
            ".clj": "clojure",
            ".cljs": "clojure",
            ".cljc": "clojure",
            
            # Elixir
            ".ex": "elixir",
            ".exs": "elixir",
            
            # Erlang
            ".erl": "erlang",
            ".hrl": "erlang",
        }
        ext = Path(file_path).suffix.lower()
        return ext_map.get(ext)
    
    def process_patch(self, patch_file: Path) -> Optional[PatchInfo]:
        """Process a patch file and return relevant information if valid."""
        try:
            owner, name, commit = self.parse_patch_filename(patch_file.name)
            
            with open(patch_file) as f:
                content = f.read()
                
            if not content.strip():
                return None
                
            # Parse the diff to get modified files
            file_changes = []
            current_file = None
            changes = []
            
            for line in content.split('\n'):
                if line.startswith('diff --git'):
                    if current_file:
                        language = self.get_language_from_file(current_file)
                        if language:  # Only add if we recognize the language
                            file_changes.append(FileChange(
                                file_path=current_file,
                                changes='\n'.join(changes),
                                language=language
                            ))
                    current_file = line.split()[-1][2:]  # Remove a/ prefix
                    changes = []
                elif current_file and line.startswith(('+', '-')):
                    changes.append(line)
            
            # Add the last file
            if current_file:
                language = self.get_language_from_file(current_file)
                if language:
                    file_changes.append(FileChange(
                        file_path=current_file,
                        changes='\n'.join(changes),
                        language=language
                    ))
            
            # Skip if no valid programming files were found
            if not file_changes:
                return None
                
            # Group files by language
            language_groups = {}
            for fc in file_changes:
                if fc.language not in language_groups:
                    language_groups[fc.language] = []
                language_groups[fc.language].append(fc)
            
            # Create patch info objects for each language group
            patch_infos = []
            for language, files in language_groups.items():
                patch_infos.append(PatchInfo(
                    repo_owner=owner,
                    repo_name=name,
                    commit_id=commit,
                    file_changes=files
                ))
            
            # Return the first patch info - we'll process one language at a time
            return patch_infos[0] if patch_infos else None
            
        except Exception as e:
            logging.error(f"Error processing patch {patch_file}: {e}")
            return None

    def parse_patch_filename(self, filename: str) -> Tuple[str, str, str]:
        """Extract repository and commit information from patch filename."""
        pattern = r"github\.com_(.+?)_(.+?)_([a-f0-9]+)\.patch"
        match = re.match(pattern, filename)
        if not match:
            raise ValueError(f"Invalid patch filename format: {filename}")
        
        owner, name, commit = match.groups()
        owner = owner.replace("_", "/")
        return (owner, name, commit)
    
    def inspect_patch_content(self, patch_file: Path) -> Optional[dict]:
        """Inspect patch content and return detailed information about the changes."""
        try:
            with open(patch_file) as f:
                content = f.read()
                
            if not content.strip():
                logging.warning(f"Empty patch file: {patch_file}")
                return None
                
            patch_info = {
                'files': [],
                'stats': {
                    'total_lines': len(content.splitlines()),
                    'additions': 0,
                    'deletions': 0
                }
            }
            
            current_file = None
            current_changes = []
            header_lines = []
            
            for line in content.split('\n'):
                if line.startswith('diff --git'):
                    if current_file:
                        patch_info['files'].append({
                            'file': current_file,
                            'changes': '\n'.join(current_changes),
                            'header': '\n'.join(header_lines)
                        })
                    current_file = line.split()[-1][2:]  # Remove a/ prefix
                    current_changes = []
                    header_lines = [line]
                elif line.startswith('+++') or line.startswith('---') or line.startswith('@@'):
                    if current_file:
                        header_lines.append(line)
                elif current_file:
                    if line.startswith('+'):
                        patch_info['stats']['additions'] += 1
                        current_changes.append(line)
                    elif line.startswith('-'):
                        patch_info['stats']['deletions'] += 1
                        current_changes.append(line)
                    else:
                        current_changes.append(line)
            
            if current_file:
                patch_info['files'].append({
                    'file': current_file,
                    'changes': '\n'.join(current_changes),
                    'header': '\n'.join(header_lines)
                })
                
            logging.info(f"Patch analysis for {patch_file}:")
            logging.info(f"  Total files modified: {len(patch_info['files'])}")
            logging.info(f"  Total lines: {patch_info['stats']['total_lines']}")
            logging.info(f"  Additions: {patch_info['stats']['additions']}")
            logging.info(f"  Deletions: {patch_info['stats']['deletions']}")
            
            for file_info in patch_info['files']:
                logging.info(f"  File: {file_info['file']}")
                logging.info(f"  Header:\n{file_info['header']}")
                logging.info(f"  Changes:\n{file_info['changes']}")
                
            return patch_info
            
        except Exception as e:
            logging.error(f"Error inspecting patch {patch_file}: {e}", exc_info=True)
            return None
