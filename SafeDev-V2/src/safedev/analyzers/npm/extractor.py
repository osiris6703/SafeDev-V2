import json
import math
import re
import tarfile
from collections import Counter
from io import BytesIO
from pathlib import Path
from typing import Dict, Optional

MAX_SOURCE_FILE_BYTES = 5 * 1024 * 1024
MAX_PACKAGE_JSON_BYTES = 1 * 1024 * 1024
MAX_ENTROPY_BYTES = 100_000
LONG_STRING_THRESHOLD = 500
ANALYZABLE_EXTENSIONS = {'.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx'}

FAST_PATTERNS = {
    'eval_calls': r'\beval\s*\(',
    'function_constructor': r'\bnew\s+Function\s*\(',
    'child_process': r'child_process|require\s*\(\s*["\']child_process',
    'exec_calls': r'\bexec\s*\(|\bexecSync\s*\(|\bexecFile\s*\(',
    'filesystem': r'\bfs\.\w+|require\s*\(\s*["\']fs["\']',
    'network_http': r'\bhttp\.\w+|\bhttps\.\w+|require\s*\(\s*["\']https?["\']|\bfetch\s*\(|\baxios\b|\bnode-fetch\b',
    'network_dns': r'\bdns\.\w+|require\s*\(\s*["\']dns["\']',
    'process_access': r'\bprocess\.env\b|\bprocess\.argv\b|\bprocess\.exit\b|\bprocess\.pid\b',
    'crypto': r'\bcrypto\.\w+|require\s*\(\s*["\']crypto["\']',
    'dynamic_require': r'require\s*\(\s*[^"\']',
    'require_calls': r'require\s*\(',
    'import_statements': r'\bimport\s+',
    'export_statements': r'\bexport\s+',
    'function_declarations': r'\bfunction\s+\w+|=>',
    'url_literals': r'https?://[^\s"\'\'<>]+',
    'base64_like': r'\batob\s*\(|\bbtoa\s*\(|Buffer\.from\s*\([^)]*,\s*["\']base64',
    'hex_escape': r'\\x[0-9a-fA-F]{2}',
    'unicode_escape': r'\\u[0-9a-fA-F]{4}|\\u\{[0-9a-fA-F]+\}',
    'atob': r'\batob\s*\(',
    'buffer_from': r'\bBuffer\.from\s*\(',
    'environment_secret_words': r'(?i)\b(?:SECRET|PASSWORD|TOKEN|API_KEY|PRIVATE_KEY|AUTH|CREDENTIAL)\b',
    'download_tools': r'\bcurl\b|\bwget\b|\bhttp\.get\b|\bhttps\.get\b',
    'shell_execution': r'\bspawn\s*\(|\bspawnSync\s*\(|\bchild_process\b',
}

class NpmFeatureExtractor:
    def __init__(self) -> None:
        feature_order_path = Path(__file__).parent.parent.parent.parent.parent / "model_artifacts" / "npm" / "feature_order.json"
        with open(feature_order_path, "r", encoding="utf-8") as f:
            self.feature_order = json.load(f)
        self.compiled_patterns = {k: re.compile(v) for k, v in FAST_PATTERNS.items()}
        self.string_pattern = re.compile(r'(["\'`])(?:(?=(\\?))\2.)*?\1')
        self.comment_pattern = re.compile(r'//.*|/\*[\s\S]*?\*/')

    def empty_features(self) -> Dict[str, float]:
        return {f: 0.0 for f in self.feature_order}

    def _calculate_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        data = data[:MAX_ENTROPY_BYTES]
        counts = Counter(data)
        length = len(data)
        return -sum((count / length) * math.log2(count / length) for count in counts.values())

    def _fast_text_stats(self, text: str) -> Dict[str, float]:
        strings = self.string_pattern.findall(text)
        string_count = len(strings)
        long_string_count = sum(1 for s in strings if len(s[0]) >= LONG_STRING_THRESHOLD)
        
        comments = self.comment_pattern.findall(text)
        comment_count = len(comments)
        
        return {
            'string_count': float(string_count),
            'long_string_count': float(long_string_count),
            'comment_count': float(comment_count)
        }

    def _process_package_json(self, content: bytes, features: Dict[str, float]) -> None:
        try:
            if len(content) > MAX_PACKAGE_JSON_BYTES:
                return
            data = json.loads(content.decode('utf-8'))
            features['package_json_valid'] = 1.0
            
            features['dependencies_count'] = float(len(data.get('dependencies', {})))
            features['dev_dependencies_count'] = float(len(data.get('devDependencies', {})))
            features['optional_dependencies_count'] = float(len(data.get('optionalDependencies', {})))
            features['peer_dependencies_count'] = float(len(data.get('peerDependencies', {})))
            
            scripts = data.get('scripts', {})
            features['scripts_count'] = float(len(scripts))
            lifecycle_scripts = {'preinstall', 'install', 'postinstall', 'prepare', 'prepublish', 'prepublishOnly', 'prepack', 'postpack'}
            features['lifecycle_script_count'] = float(sum(1 for k in scripts if k in lifecycle_scripts))
            
            bin_data = data.get('bin', {})
            if isinstance(bin_data, dict):
                features['bin_count'] = float(len(bin_data))
            elif isinstance(bin_data, str):
                features['bin_count'] = 1.0
                
            features['has_main'] = 1.0 if 'main' in data else 0.0
            features['has_module'] = 1.0 if 'module' in data else 0.0
            features['has_exports'] = 1.0 if 'exports' in data else 0.0
            features['has_types'] = 1.0 if 'types' in data or 'typings' in data else 0.0
            
        except Exception:
            pass

    def _process_file(self, filename: str, content: bytes, features: Dict[str, float], entropies: list) -> None:
        path = Path(filename)
        basename = path.name.lower()
        ext = path.suffix.lower()

        if basename == 'package.json':
            self._process_package_json(content, features)
        elif basename in ('readme', 'readme.md', 'readme.txt'):
            features['has_readme'] = 1.0
        elif basename.startswith('license'):
            features['has_license'] = 1.0

        if ext in ANALYZABLE_EXTENSIONS:
            if len(content) > MAX_SOURCE_FILE_BYTES:
                return
            
            features['source_file_count'] += 1.0
            if ext in ('.js', '.mjs', '.cjs', '.jsx'):
                features['js_file_count'] += 1.0
            elif ext in ('.ts', '.tsx'):
                features['ts_file_count'] += 1.0
                
            features['source_bytes'] += len(content)
            
            try:
                text = content.decode('utf-8', errors='ignore')
                features['source_lines'] += text.count('\n') + 1.0
                
                stats = self._fast_text_stats(text)
                features['string_count'] += stats['string_count']
                features['long_string_count'] += stats['long_string_count']
                features['comment_count'] += stats['comment_count']
                
                for key, pattern in self.compiled_patterns.items():
                    if key in features:
                        features[key] += float(len(pattern.findall(text)))
                
                entropy = self._calculate_entropy(content)
                entropies.append(entropy)
                if entropy >= 5.0:
                    features['high_entropy_files'] += 1.0
                    
            except Exception:
                pass

    def _finalize_features(self, features: Dict[str, float], entropies: list) -> Dict[str, float]:
        if entropies:
            features['source_entropy_mean'] = sum(entropies) / len(entropies)
            
        if features['string_count'] > 0:
            features['long_string_ratio'] = features['long_string_count'] / features['string_count']
            
        return {f: features.get(f, 0.0) for f in self.feature_order}

    def extract_from_tarball(self, archive_bytes: bytes) -> Dict[str, float]:
        features = self.empty_features()
        entropies = []
        
        try:
            with tarfile.open(fileobj=BytesIO(archive_bytes), mode='r:gz') as tar:
                for member in tar.getmembers():
                    if member.isfile():
                        try:
                            f = tar.extractfile(member)
                            if f:
                                content = f.read()
                                self._process_file(member.name, content, features, entropies)
                        except Exception:
                            continue
        except Exception:
            pass
            
        return self._finalize_features(features, entropies)

    def extract_from_directory(self, package_dir: Path) -> Dict[str, float]:
        features = self.empty_features()
        entropies = []
        
        for path in package_dir.rglob('*'):
            if path.is_file():
                try:
                    with open(path, 'rb') as f:
                        content = f.read()
                        # Use path relative to package_dir as filename
                        filename = str(path.relative_to(package_dir))
                        self._process_file(filename, content, features, entropies)
                except Exception:
                    continue
                    
        return self._finalize_features(features, entropies)
