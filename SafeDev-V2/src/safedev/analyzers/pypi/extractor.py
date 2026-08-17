import ast
import io
import os
import re
import tarfile
import zipfile
import numpy as np
from pathlib import Path
from typing import Dict, Any, List, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

LONG_STRING_THRESHOLD = 500
LONG_LINE_THRESHOLD = 200
VERY_LARGE_FILE_THRESHOLD = 10 * 1024 * 1024
MAX_TOTAL_EXTRACTED_BYTES = 250 * 1024 * 1024
MAX_SINGLE_FILE_BYTES = 25 * 1024 * 1024
MAX_PYTHON_SOURCE_BYTES = 10 * 1024 * 1024
MAX_FILES_PER_PACKAGE = 10000

SOURCE_EXTENSIONS = {'.py', '.pyw', '.pyi'}
NATIVE_EXTENSIONS = {'.so', '.dll', '.dylib', '.pyd'}
EXECUTABLE_EXTENSIONS = {'.exe', '.bin', '.elf', '.com'}
COMPRESSED_EXTENSIONS = {'.gz', '.bz2', '.xz', '.zst', '.lz', '.lz4'}
ARCHIVE_EXTENSIONS = {'.zip', '.tar', '.gz', '.tgz', '.bz2', '.xz', '.whl'}
BINARY_EXTENSIONS = {'.so', '.dll', '.dylib', '.pyd', '.exe', '.bin', '.class'}

CREDENTIAL_KEYWORDS = ['password', 'passwd', 'secret', 'credential', 'credentials', 'private_key', 'privatekey', 'access_key', 'secret_key']
TOKEN_KEYWORDS = ['api_key', 'apikey', 'token', 'auth_token', 'bearer', 'authorization', 'jwt']
INSTALL_HOOK_KEYWORDS = ['build_ext', 'cmdclass', 'build_py', 'install', 'bdist', 'setuptools.command', 'distutils.command']
POST_INSTALL_KEYWORDS = ['post_install', 'postinstall', 'entry_points', 'console_scripts']

STDLIB_MODULES = {
    'abc', 'argparse', 'ast', 'asyncio', 'base64', 'collections', 'concurrent',
    'contextlib', 'copy', 'csv', 'dataclasses', 'datetime', 'decimal', 'difflib',
    'email', 'enum', 'errno', 'functools', 'gc', 'glob', 'gzip', 'hashlib', 'heapq',
    'hmac', 'html', 'http', 'importlib', 'inspect', 'io', 'itertools', 'json',
    'logging', 'math', 'mimetypes', 'multiprocessing', 'os', 'pathlib', 'pickle',
    'platform', 'plistlib', 'queue', 'random', 're', 'secrets', 'shlex', 'shutil',
    'signal', 'socket', 'sqlite3', 'ssl', 'statistics', 'string', 'struct',
    'subprocess', 'sys', 'tempfile', 'textwrap', 'threading', 'time', 'traceback',
    'types', 'typing', 'unicodedata', 'unittest', 'urllib', 'uuid', 'warnings',
    'weakref', 'xml', 'zipfile', 'zlib'
}


class SecurityASTVisitor(ast.NodeVisitor):
    def __init__(self):
        self.eval_count = 0
        self.exec_count = 0
        self.compile_count = 0
        self.globals_access_count = 0
        self.locals_access_count = 0
        self.os_system_count = 0
        self.subprocess_count = 0
        self.popen_count = 0
        self.shell_true_count = 0
        self.file_open_count = 0
        self.pathlib_count = 0
        self.file_delete_count = 0
        self.chmod_count = 0
        self.tempfile_count = 0
        self.socket_count = 0
        self.http_client_count = 0
        self.urlopen_count = 0
        self.requests_count = 0
        self.environment_access_count = 0
        self.base64_count = 0
        self.decode_count = 0
        self.encode_count = 0
        self.hex_decode_count = 0
        self.marshal_count = 0
        self.pickle_count = 0
        self.compressed_payload_count = 0
        self.import_statement_count = 0
        self.string_literal_count = 0
        self.long_string_count = 0
        self.exception_handler_count = 0
        self.lambda_count = 0
        self.function_definition_count = 0
        self.class_definition_count = 0
        self.max_ast_depth = 0
        self._current_depth = 0
        self.imports = set()

    def generic_visit(self, node):
        self._current_depth += 1
        if self._current_depth > self.max_ast_depth:
            self.max_ast_depth = self._current_depth
        super().generic_visit(node)
        self._current_depth -= 1

    def visit_Import(self, node: ast.Import):
        self.import_statement_count += 1
        for alias in node.names:
            self.imports.add(alias.name.split('.')[0])
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        self.import_statement_count += 1
        if node.module:
            self.imports.add(node.module.split('.')[0])
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant):
        if isinstance(node.value, str):
            self.string_literal_count += 1
            if len(node.value) >= LONG_STRING_THRESHOLD:
                self.long_string_count += 1
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        self.exception_handler_count += 1
        self.generic_visit(node)

    def visit_Lambda(self, node: ast.Lambda):
        self.lambda_count += 1
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self.function_definition_count += 1
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self.function_definition_count += 1
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef):
        self.class_definition_count += 1
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        name = self._get_call_name(node.func).lower()
        if name:
            if name == 'eval':
                self.eval_count += 1
            elif name == 'exec':
                self.exec_count += 1
            elif name == 'compile':
                self.compile_count += 1
            elif name == 'globals':
                self.globals_access_count += 1
            elif name == 'locals':
                self.locals_access_count += 1
            elif name in ('os.system', 'system'):
                self.os_system_count += 1
            elif name.startswith('subprocess.') or name == 'subprocess':
                self.subprocess_count += 1
            elif name.endswith('popen'):
                self.popen_count += 1
            elif name in ('open', 'io.open', 'builtins.open'):
                self.file_open_count += 1
            elif name.startswith('pathlib.'):
                self.pathlib_count += 1
            elif name in ('os.remove', 'os.unlink', 'path.unlink', 'path.rmdir', 'shutil.rmtree'):
                self.file_delete_count += 1
            elif name.endswith('chmod'):
                self.chmod_count += 1
            elif name.startswith('tempfile.'):
                self.tempfile_count += 1
            elif name.startswith('socket.'):
                self.socket_count += 1
            elif name.startswith('requests.'):
                self.requests_count += 1
            elif name in ('urllib.request.urlopen', 'urlopen'):
                self.urlopen_count += 1
            elif any(part in name for part in ('http.client', 'httpx.', 'aiohttp.', 'urllib3.')):
                self.http_client_count += 1
            elif name in ('os.getenv', 'os.environ.get', 'os.environ.__getitem__'):
                self.environment_access_count += 1
            elif 'base64' in name:
                self.base64_count += 1
            elif name.endswith('.decode'):
                self.decode_count += 1
            elif name.endswith('.encode'):
                self.encode_count += 1
            elif 'unhexlify' in name or 'fromhex' in name:
                self.hex_decode_count += 1
            elif name.startswith('marshal.'):
                self.marshal_count += 1
            elif name.startswith('pickle.'):
                self.pickle_count += 1
            elif any(part in name for part in ('gzip.', 'zlib.', 'bz2.', 'lzma.', 'zipfile.')):
                self.compressed_payload_count += 1

        for kw in node.keywords:
            if kw.arg == 'shell' and isinstance(kw.value, ast.Constant) and bool(kw.value.value):
                self.shell_true_count += 1

        self.generic_visit(node)

    @staticmethod
    def _get_call_name(node) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            val = SecurityASTVisitor._get_call_name(node.value)
            return f"{val}.{node.attr}" if val else node.attr
        return ""


def _process_single_python_file(item: Tuple[str, bytes]) -> Dict[str, Any]:
    """Worker function for parallel multi-threaded Python source parsing."""
    name, content = item
    res = {
        'total_python_lines': 0,
        'blank_lines': 0,
        'comment_lines': 0,
        'long_line_count': 0,
        'http_url_count': 0,
        'ip_address_literal_count': 0,
        'system_command_string_count': 0,
        'credential_keyword_count': 0,
        'token_keyword_count': 0,
        'install_hook_keyword_count': 0,
        'post_install_keyword_count': 0,
        'ast_success': 0,
        'ast_failure': 0,
        'imports': set(),
        'ast_max_depth': 0,
        'file_size': len(content),
    }

    try:
        text = content.decode('utf-8')
    except UnicodeDecodeError:
        res['ast_failure'] = 1
        return res

    lines = text.split('\n')
    res['total_python_lines'] = len(lines)
    for line in lines:
        stripped = line.strip()
        if not stripped:
            res['blank_lines'] += 1
        elif stripped.startswith('#'):
            res['comment_lines'] += 1
        if len(line) >= LONG_LINE_THRESHOLD:
            res['long_line_count'] += 1

    lower_text = text.lower()
    res['http_url_count'] = len(re.findall(r'https?://[^\s\"\'<>]+', text, re.IGNORECASE))
    res['ip_address_literal_count'] = len(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text))
    res['system_command_string_count'] = len(re.findall(r'\b(?:curl|wget|bash|sh|powershell|cmd|chmod|chown|rm\s+-rf)\b', text))

    for kw in CREDENTIAL_KEYWORDS:
        res['credential_keyword_count'] += lower_text.count(kw)
    for kw in TOKEN_KEYWORDS:
        res['token_keyword_count'] += lower_text.count(kw)
    for kw in INSTALL_HOOK_KEYWORDS:
        res['install_hook_keyword_count'] += lower_text.count(kw)
    for kw in POST_INSTALL_KEYWORDS:
        res['post_install_keyword_count'] += lower_text.count(kw)

    try:
        tree = ast.parse(text, filename=name)
        res['ast_success'] = 1
        visitor = SecurityASTVisitor()
        visitor.visit(tree)

        res['eval_count'] = visitor.eval_count
        res['exec_count'] = visitor.exec_count
        res['compile_count'] = visitor.compile_count
        res['globals_access_count'] = visitor.globals_access_count
        res['locals_access_count'] = visitor.locals_access_count
        res['os_system_count'] = visitor.os_system_count
        res['subprocess_count'] = visitor.subprocess_count
        res['popen_count'] = visitor.popen_count
        res['shell_true_count'] = visitor.shell_true_count
        res['file_open_count'] = visitor.file_open_count
        res['pathlib_count'] = visitor.pathlib_count
        res['file_delete_count'] = visitor.file_delete_count
        res['chmod_count'] = visitor.chmod_count
        res['tempfile_count'] = visitor.tempfile_count
        res['socket_count'] = visitor.socket_count
        res['http_client_count'] = visitor.http_client_count
        res['urlopen_count'] = visitor.urlopen_count
        res['requests_count'] = visitor.requests_count
        res['environment_access_count'] = visitor.environment_access_count
        res['base64_count'] = visitor.base64_count
        res['decode_count'] = visitor.decode_count
        res['encode_count'] = visitor.encode_count
        res['hex_decode_count'] = visitor.hex_decode_count
        res['marshal_count'] = visitor.marshal_count
        res['pickle_count'] = visitor.pickle_count
        res['compressed_payload_count'] = visitor.compressed_payload_count
        res['import_statement_count'] = visitor.import_statement_count
        res['string_literal_count'] = visitor.string_literal_count
        res['long_string_count'] = visitor.long_string_count
        res['exception_handler_count'] = visitor.exception_handler_count
        res['lambda_count'] = visitor.lambda_count
        res['function_definition_count'] = visitor.function_definition_count
        res['class_definition_count'] = visitor.class_definition_count
        res['ast_max_depth'] = visitor.max_ast_depth
        res['imports'] = visitor.imports

    except Exception:
        res['ast_failure'] = 1

    return res


class PyPIFeatureExtractor:
    def __init__(self, feature_order_path=None):
        if feature_order_path is None:
            feature_order_path = (
                Path(__file__).resolve().parents[4]
                / "model_artifacts" / "pypi" / "feature_order.txt"
            )
        self.feature_order = []
        try:
            with open(feature_order_path, 'r', encoding='utf-8') as f:
                self.feature_order = [line.strip() for line in f if line.strip()]
        except Exception:
            self.feature_order = []

    def empty_features(self) -> Dict[str, float]:
        return {f: 0.0 for f in self.feature_order}

    def _safe_archive_path(self, name: str) -> str:
        normalized = name.replace('\\', '/').lstrip('/')
        parts = normalized.split('/')
        if '..' in parts:
            return ""
        return normalized

    def _read_archive_members(self, archive_bytes: bytes, archive_name: str) -> List[Tuple[str, bytes]]:
        if archive_name.endswith('.zip') or archive_name.endswith('.whl'):
            return self._read_zip(archive_bytes)
        elif archive_name.endswith('.tar.gz') or archive_name.endswith('.tgz') or archive_name.endswith('.tar'):
            return self._read_tar(archive_bytes)
        return []

    def _read_zip(self, archive_bytes: bytes) -> List[Tuple[str, bytes]]:
        members = []
        try:
            with zipfile.ZipFile(io.BytesIO(archive_bytes)) as zf:
                for idx, info in enumerate(zf.infolist()):
                    if idx >= MAX_FILES_PER_PACKAGE:
                        break
                    if info.is_dir():
                        continue
                    if info.file_size > MAX_SINGLE_FILE_BYTES:
                        continue
                    path = self._safe_archive_path(info.filename)
                    if not path:
                        continue
                    try:
                        content = zf.read(info)
                        members.append((path, content))
                    except Exception:
                        pass
        except Exception:
            pass
        return members

    def _read_tar(self, archive_bytes: bytes) -> List[Tuple[str, bytes]]:
        members = []
        try:
            with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode='r:*') as tf:
                for idx, info in enumerate(tf):
                    if idx >= MAX_FILES_PER_PACKAGE:
                        break
                    if not info.isfile():
                        continue
                    if info.size > MAX_SINGLE_FILE_BYTES:
                        continue
                    path = self._safe_archive_path(info.name)
                    if not path:
                        continue
                    try:
                        f = tf.extractfile(info)
                        if f:
                            content = f.read()
                            members.append((path, content))
                    except Exception:
                        pass
        except Exception:
            pass
        return members

    def extract_from_archive(self, archive_bytes: bytes, archive_name: str) -> Dict[str, float]:
        features = self.empty_features()
        all_imports = set()

        members = self._read_archive_members(archive_bytes, archive_name)
        features['total_files'] = float(len(members))

        directories = set()
        max_depth = 0
        python_items = []

        for name, content in members:
            parts = name.split('/')
            if len(parts) > 1:
                directories.add('/'.join(parts[:-1]))
            max_depth = max(max_depth, len(parts))

            lower_name = name.lower()
            name_only = parts[-1].lower()
            ext = Path(lower_name).suffix

            if name_only == 'setup.py':
                features['setup_py_present'] = 1.0
            if name_only == 'pyproject.toml':
                features['pyproject_present'] = 1.0
            if name_only == 'setup.cfg':
                features['setup_cfg_present'] = 1.0

            if ext in NATIVE_EXTENSIONS:
                features['native_library_count'] += 1
            if ext in EXECUTABLE_EXTENSIONS:
                features['executable_file_count'] += 1
            if ext in BINARY_EXTENSIONS:
                features['binary_file_count'] += 1
            if ext in COMPRESSED_EXTENSIONS:
                features['compressed_file_count'] += 1
            if ext in ARCHIVE_EXTENSIONS:
                features['archive_file_count'] += 1
            if name_only.startswith('.'):
                features['hidden_file_count'] += 1
            if len(content) > VERY_LARGE_FILE_THRESHOLD:
                features['very_large_file_count'] += 1

            if ext in SOURCE_EXTENSIONS:
                python_items.append((name, content))

        python_files = len(python_items)
        total_source_bytes = sum(len(c) for _, c in python_items)
        max_python_file_size = max((len(c) for _, c in python_items), default=0)

        total_python_lines = 0
        blank_lines = 0
        comment_lines = 0
        long_line_count = 0
        ast_success = 0
        ast_failure = 0

        # Parallel multi-threaded processing of Python source files
        num_workers = min(16, (os.cpu_count() or 4) * 2)
        if python_items:
            with ThreadPoolExecutor(max_workers=num_workers) as executor:
                futures = [executor.submit(_process_single_python_file, item) for item in python_items]
                for future in as_completed(futures):
                    res = future.result()
                    total_python_lines += res['total_python_lines']
                    blank_lines += res['blank_lines']
                    comment_lines += res['comment_lines']
                    long_line_count += res['long_line_count']
                    ast_success += res['ast_success']
                    ast_failure += res['ast_failure']

                    features['http_url_count'] += res['http_url_count']
                    features['ip_address_literal_count'] += res['ip_address_literal_count']
                    features['system_command_string_count'] += res['system_command_string_count']
                    features['credential_keyword_count'] += res['credential_keyword_count']
                    features['token_keyword_count'] += res['token_keyword_count']
                    features['install_hook_keyword_count'] += res['install_hook_keyword_count']
                    features['post_install_keyword_count'] += res['post_install_keyword_count']

                    for key in [
                        'eval_count', 'exec_count', 'compile_count', 'globals_access_count',
                        'locals_access_count', 'os_system_count', 'subprocess_count', 'popen_count',
                        'shell_true_count', 'file_open_count', 'pathlib_count', 'file_delete_count',
                        'chmod_count', 'tempfile_count', 'socket_count', 'http_client_count',
                        'urlopen_count', 'requests_count', 'environment_access_count',
                        'base64_count', 'decode_count', 'encode_count', 'hex_decode_count',
                        'marshal_count', 'pickle_count', 'compressed_payload_count',
                        'import_statement_count', 'string_literal_count', 'long_string_count',
                        'exception_handler_count', 'lambda_count', 'function_definition_count',
                        'class_definition_count'
                    ]:
                        features[key] += res.get(key, 0)

                    features['max_ast_depth'] = max(features['max_ast_depth'], res['ast_max_depth'])
                    all_imports.update(res['imports'])

        # Post-processing structural features
        features['python_files'] = float(python_files)
        features['python_file_ratio'] = float(python_files / len(members)) if len(members) > 0 else 0.0
        features['total_source_bytes'] = float(total_source_bytes)
        features['average_python_file_size'] = float(total_source_bytes / python_files) if python_files > 0 else 0.0
        features['max_python_file_size'] = float(max_python_file_size)
        features['directory_count'] = float(len(directories))
        features['max_path_depth'] = float(max_depth)

        # Post-processing AST features
        features['total_python_lines'] = float(total_python_lines)
        features['blank_line_ratio'] = float(blank_lines / total_python_lines) if total_python_lines > 0 else 0.0
        features['comment_line_ratio'] = float(comment_lines / total_python_lines) if total_python_lines > 0 else 0.0
        features['long_line_count'] = float(long_line_count)

        total_ast = ast_success + ast_failure
        features['ast_parse_success_ratio'] = float(ast_success / total_ast) if total_ast > 0 else 0.0
        features['ast_parse_failure_count'] = float(ast_failure)

        features['unique_import_count'] = float(len(all_imports))
        features['stdlib_import_count'] = float(sum(1 for m in all_imports if m in STDLIB_MODULES))
        features['third_party_import_count'] = float(sum(1 for m in all_imports if m not in STDLIB_MODULES))

        # Cleanup and finalize
        final_features = {}
        for fname in self.feature_order:
            val = features.get(fname, 0.0)
            if not np.isfinite(val):
                val = 0.0
            final_features[fname] = float(val)

        return final_features
