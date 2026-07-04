import os

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


YARA_RULES_DIR = "yara_rules"


def load_all_rules():
    """
    Load all .yar files from the yara_rules/ folder.
    Returns compiled rules ready to scan files.
    """
    if not YARA_AVAILABLE:
        return None

    if not os.path.exists(YARA_RULES_DIR):
        os.makedirs(YARA_RULES_DIR)
        return None

    rule_files = {}
    for f in os.listdir(YARA_RULES_DIR):
        if f.endswith('.yar') or f.endswith('.yara'):
            full_path = os.path.join(YARA_RULES_DIR, f)
            rule_files[f] = full_path

    if not rule_files:
        return None

    try:
        rules = yara.compile(filepaths=rule_files)
        return rules
    except Exception as e:
        print(f'[yara] Rule compilation error: {e}')
        return None


def scan_with_yara(file_path):
    """
    Scan a file against all loaded YARA rules.
    Returns list of matched rules with their descriptions.
    """
    if not YARA_AVAILABLE:
        return {
            'available' : False,
            'error'     : 'yara-python not installed. Run: pip install yara-python',
            'matches'   : []
        }

    if not os.path.exists(file_path):
        return {'error': 'File not found', 'matches': []}

    rules = load_all_rules()

    if rules is None:
        return {
            'available' : True,
            'matches'   : [],
            'note'      : 'No YARA rules loaded. Add .yar files to yara_rules/ folder'
        }

    try:
        matches = rules.match(file_path, timeout=30)
        match_results = []

        for match in matches:
            match_results.append({
                'rule'       : match.rule,
                'tags'       : list(match.tags),
                'strings'    : [(hex(s.instances[0].offset),
                                 s.identifier) for s in match.strings[:5]],
                'description': match.meta.get('description', 'No description'),
                'author'     : match.meta.get('author', 'Unknown'),
                'severity'   : match.meta.get('severity', 'medium'),
            })

        return {
            'available'    : True,
            'matches'      : match_results,
            'total_matches': len(match_results),
            'is_malicious' : len(match_results) > 0
        }

    except yara.TimeoutError:
        return {'error': 'YARA scan timed out (file too large)', 'matches': []}
    except Exception as e:
        return {'error': f'YARA scan error: {str(e)}', 'matches': []}