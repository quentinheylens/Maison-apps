"""Read only reviewed configuration families; never export .storage or secrets."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import yaml

MAX_FILE = 512 * 1024
MAX_TOTAL = 4 * 1024 * 1024
FAMILIES = {'automations.yaml', 'scripts.yaml', 'scenes.yaml'}
DIRECTORIES = {'automations', 'scripts', 'packages', 'blueprints'}

class ConfigError(Exception):
    pass

class Loader(yaml.SafeLoader):
    pass

def mapping(loader, node):
    pairs = loader.construct_pairs(node, deep=True)
    result = {}
    for key, value in pairs:
        if not isinstance(key, (str, int, float, bool)) or key in result:
            raise ConfigError('duplicate_or_invalid_key')
        result[key] = value
    return result

Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
def tagged(loader, suffix, node):
    if not isinstance(node, yaml.ScalarNode):
        raise ConfigError('unsupported_tag')
    if suffix not in {'secret', 'input', 'include', 'include_dir_list', 'include_dir_named',
                      'include_dir_merge_list', 'include_dir_merge_named', 'env_var'}:
        raise ConfigError('unsupported_tag')
    # Environment values are never resolved; secret values never substituted.
    return {'!' + suffix: loader.construct_scalar(node)}
Loader.add_multi_constructor('!', tagged)

def ordinary(root, relative):
    relative = PurePosixPath(relative)
    if relative.is_absolute() or any(p in {'..', '.'} or p.startswith('.') for p in relative.parts):
        raise ConfigError('invalid_path')
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in relative.parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(relative.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            meta = os.fstat(fd)
            if not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1 or meta.st_size > MAX_FILE:
                raise ConfigError('bounded_ordinary_file_required')
            raw = os.read(fd, MAX_FILE + 1)
            if len(raw) > MAX_FILE:
                raise ConfigError('file_too_large')
            return raw
        finally:
            os.close(fd)
    finally:
        os.close(directory)

def parse(raw):
    # Bound nesting and node count before construction, rejecting YAML expansion.
    depth, nodes = 0, 0
    for event in yaml.parse(raw, Loader=Loader):
        nodes += 1
        if nodes > 50000 or isinstance(event, yaml.events.AliasEvent) or getattr(event, 'anchor', None):
            raise ConfigError('yaml_expansion_refused')
        if isinstance(event, (yaml.events.MappingStartEvent,yaml.events.SequenceStartEvent)):
            depth += 1
            if depth > 32: raise ConfigError('yaml_depth_refused')
        elif isinstance(event, (yaml.events.MappingEndEvent,yaml.events.SequenceEndEvent)):
            depth -= 1
    return yaml.load(raw, Loader=Loader)

class ConfigReader:
    def __init__(self, root, privacy):
        self.root = Path(root).resolve()
        self.privacy = privacy

    def snapshot(self):
        paths = []
        consumed = {}
        def read(name):
            if name not in consumed:
                raw = ordinary(self.root,name)
                consumed[name] = raw
                if sum(map(len,consumed.values())) > MAX_TOTAL: raise ConfigError('export_budget_exceeded')
                return raw
            return consumed[name]
        for name in sorted(FAMILIES):
            if (self.root / name).is_symlink(): raise ConfigError('symlink_refused')
            if (self.root / name).exists():
                paths.append(name)
        for family in sorted(DIRECTORIES):
            folder = self.root / family
            if folder.is_symlink():
                raise ConfigError('symlink_refused')
            if folder.exists():
                for path in sorted(folder.rglob('*')):
                    if path.is_symlink():
                        raise ConfigError('symlink_refused')
                    if path.is_file() and path.suffix in {'.yaml', '.yml'}:
                        paths.append(path.relative_to(self.root).as_posix())
        paths = set(paths)
        if (self.root/'configuration.yaml').exists():
            config = parse(read('configuration.yaml'))
            if isinstance(config,dict):
                selected = {key:value for key,value in config.items()
                            if str(key).split(' ')[0] in {'automation','script','scene'}}
                if isinstance(config.get('homeassistant'),dict):
                    selected['packages'] = config['homeassistant'].get('packages',{})
                pending = [('',selected)]
            else: pending = []
        else: pending = []
        visited = set()
        def includes(value):
            if isinstance(value,dict):
                for key,item in value.items():
                    if str(key).startswith('!include') and isinstance(item,str): yield key,item
                    else: yield from includes(item)
            elif isinstance(value,list):
                for item in value: yield from includes(item)
        pending.extend((name,parse(read(name))) for name in sorted(paths))
        while pending:
            name,value = pending.pop()
            if name in visited: continue
            visited.add(name)
            if len(visited)>256: raise ConfigError('include_budget_exceeded')
            for tag,relative in includes(value):
                part = PurePosixPath(relative)
                if part.is_absolute() or any(p.startswith('.') or p == '..' for p in part.parts):
                    raise ConfigError('include_path_refused')
                target = PurePosixPath(name).parent/part
                if target.name in {'secrets.yaml','configuration.yaml'}:
                    raise ConfigError('sensitive_include_refused')
                if tag == '!include': targets = [target.as_posix()]
                else:
                    folder = self.root/target
                    if folder.is_symlink(): raise ConfigError('symlink_refused')
                    targets = []
                    for path in sorted(folder.rglob('*')):
                        if path.is_symlink(): raise ConfigError('symlink_refused')
                        if path.is_file() and path.suffix in {'.yaml','.yml'}:
                            targets.append(path.relative_to(self.root).as_posix())
                for item in targets:
                    if PurePosixPath(item).suffix not in {'.yaml','.yml'}: raise ConfigError('non_yaml_include')
                    if item not in paths:
                        paths.add(item)
                        pending.append((item,parse(read(item))))
        if len(paths) > 256:
            raise ConfigError('file_count_exceeded')
        privacy = self.effective_privacy()
        total = 0
        result = []
        for name in sorted(paths):
            raw = read(name)
            total += len(raw)
            if total > MAX_TOTAL:
                raise ConfigError('export_budget_exceeded')
            value = privacy.clean(parse(raw))
            data = json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False).encode()
            result.append({'path': name, 'sha256': hashlib.sha256(data).hexdigest(), 'definition': value})
        for name, raw in consumed.items():
            if ordinary(self.root,name) != raw: raise ConfigError('configuration_changed_during_snapshot')
        digest = hashlib.sha256(json.dumps(result, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
        return {'revision': digest, 'files': result, 'read_only_projection': True,
                'excluded': ['configuration.yaml', '.storage', 'secrets.yaml', 'databases', 'logs', 'backups'],
                'limitations': ['Free text is redacted; projections are not deployment inputs.',
                               'Includes outside the exported families require offline reviewed synchronization.']}

    def effective_privacy(self):
        # Known literal secret values are read locally only to remove accidental copies.
        terms = list(self.privacy.terms)
        secret = self.root / 'secrets.yaml'
        if secret.is_symlink(): raise ConfigError('symlink_refused')
        if secret.exists():
            secrets = parse(ordinary(self.root, 'secrets.yaml'))
            def collect(value):
                if isinstance(value, dict):
                    for item in value.values(): collect(item)
                elif isinstance(value, list):
                    for item in value: collect(item)
                elif value is not None and len(str(value)) >= 3:
                    terms.append(str(value))
            collect(secrets)
        return type(self.privacy)(terms)
