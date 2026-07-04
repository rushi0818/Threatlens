import os
import re
import string
import struct

# pefile is for analyzing Windows .exe/.dll files
try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False


# ── File type signatures (magic bytes) ────────────────────────
# Every file type starts with specific bytes at the beginning
# This tells us the REAL type, not just the extension

FILE_SIGNATURES = {
    b'\x4d\x5a'                : 'Windows EXE/DLL',
    b'\x7f\x45\x4c\x46'       : 'Linux ELF Executable',
    b'\x25\x50\x44\x46'       : 'PDF Document',
    b'\x50\x4b\x03\x04'       : 'ZIP/Office Document',
    b'\xd0\xcf\x11\xe0'       : 'Old Office Document (DOC/XLS)',
    b'\x52\x61\x72\x21'       : 'RAR Archive',
    b'\x1f\x8b'               : 'GZIP Archive',
    b'\x4d\x5a\x90\x00'       : 'Windows PE Executable',
    b'\x23\x21'               : 'Script File (Shebang)',
    b'\xff\xfe'               : 'Unicode Text',
    b'\xef\xbb\xbf'           : 'UTF-8 Text with BOM',
}

# ── Suspicious Windows API functions ──────────────────────────
# These are functions malware commonly uses
# Finding these strings inside a file = red flag

SUSPICIOUS_APIS = {
    # Process and code injection
    'CreateRemoteThread'    : 'Process injection technique',
    'VirtualAllocEx'        : 'Memory allocation in remote process',
    'WriteProcessMemory'    : 'Writing to another process memory',
    'OpenProcess'           : 'Opening another process (injection)',
    'NtCreateThreadEx'      : 'Low-level thread creation (evasion)',

    # Registry operations (persistence)
    'RegSetValueEx'         : 'Writing to Windows registry (persistence)',
    'RegCreateKeyEx'        : 'Creating registry key (persistence)',
    'HKEY_CURRENT_USER'     : 'Registry key for user persistence',
    'HKEY_LOCAL_MACHINE'    : 'Registry key for system persistence',

    # Network operations
    'WSAStartup'            : 'Network socket initialization',
    'InternetOpenUrl'       : 'Opening URL (network communication)',
    'HttpSendRequest'       : 'Sending HTTP request',
    'connect'               : 'Network connection attempt',
    'WinHttpOpen'           : 'HTTP client initialization',

    # File system (dropping files)
    'CreateFile'            : 'File creation/access',
    'WriteFile'             : 'Writing files to disk',
    'CopyFile'              : 'Copying files (spreading)',
    'DeleteFile'            : 'Deleting files (cleanup/destruction)',

    # Evasion techniques
    'IsDebuggerPresent'     : 'Debugger detection (anti-analysis)',
    'CheckRemoteDebuggerPresent': 'Remote debugger check (anti-analysis)',
    'GetTickCount'          : 'Timing check (sandbox evasion)',
    'Sleep'                 : 'Delay execution (sandbox evasion)',
    'VirtualProtect'        : 'Change memory permissions (unpacking)',

    # Encryption/encoding (often used to hide malware)
    'CryptEncrypt'          : 'Encryption function (ransomware indicator)',
    'CryptDecrypt'          : 'Decryption function',
    'CryptGenKey'           : 'Key generation (ransomware indicator)',

    # Command execution
    'ShellExecute'          : 'Executing commands/programs',
    'WinExec'               : 'Running executable',
    'CreateProcess'         : 'Creating new process',
    'cmd.exe'               : 'Command prompt execution',
    'powershell'            : 'PowerShell execution (common in malware)',

    # Keylogging
    'SetWindowsHookEx'      : 'Keyboard/mouse hooking (keylogger)',
    'GetAsyncKeyState'      : 'Key state monitoring (keylogger)',

    # Screenshot/spyware
    'BitBlt'                : 'Screen capture function',
    'GetDC'                 : 'Device context (screen capture)',
}

# ── Ransomware specific indicators ────────────────────────────
RANSOMWARE_INDICATORS = [
    'encrypt', 'decrypt', 'ransom', 'bitcoin', 'wallet',
    'your files', 'pay now', 'deadline', '.locked', '.encrypted',
    'AES', 'RSA', 'CryptEncrypt', 'CryptGenKey',
    'README.txt', 'HOW_TO_DECRYPT', 'DECRYPT_INSTRUCTIONS'
]

# ── Trojan/RAT indicators ─────────────────────────────────────
RAT_INDICATORS = [
    'keylog', 'screenshot', 'webcam', 'microphone',
    'remote control', 'backdoor', 'reverse shell',
    'command and control', 'c2', 'bot', 'zombie'
]


def get_file_type(file_path):
    """
    Read first few bytes of file and check against known signatures.
    This tells us the REAL file type regardless of extension.
    """
    try:
        with open(file_path, 'rb') as f:
            header = f.read(8)

        for signature, file_type in FILE_SIGNATURES.items():
            if header.startswith(signature):
                return file_type

        # Check if it looks like plain text
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                sample = f.read(100)
            if all(c in string.printable for c in sample):
                return 'Plain Text / Script'
        except Exception:
            pass

        return 'Unknown Binary'

    except Exception as e:
        return f'Could not read: {str(e)}'


def extract_strings(file_path, min_length=4):
    """
    Extract all readable ASCII strings from a binary file.
    This is exactly what the 'strings' command does on Linux.
    Even inside malware binaries, readable text leaks out —
    like URLs, IP addresses, error messages, file paths.
    """
    strings_found = []

    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        # Find sequences of printable ASCII characters
        current = []
        for byte in data:
            char = chr(byte)
            if char in string.printable and char not in '\t\n\r\x0b\x0c':
                current.append(char)
            else:
                if len(current) >= min_length:
                    strings_found.append(''.join(current))
                current = []

        # Don't miss the last one
        if len(current) >= min_length:
            strings_found.append(''.join(current))

    except Exception as e:
        strings_found = [f'Error reading file: {str(e)}']

    return strings_found


def extract_network_iocs(strings_list):
    """
    From extracted strings, pull out network indicators:
    - IP addresses
    - URLs
    - Domain names
    - Email addresses
    """
    iocs = {
        'ips'     : [],
        'urls'    : [],
        'emails'  : [],
        'domains' : []
    }

    ip_pattern     = re.compile(r'\b(\d{1,3}\.){3}\d{1,3}\b')
    url_pattern    = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]{4,}')
    email_pattern  = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')

    for s in strings_list:
        # IPs
        for ip in ip_pattern.findall(s):
            if ip not in iocs['ips'] and not ip.startswith('0.'):
                iocs['ips'].append(ip)

        # URLs
        for url in url_pattern.findall(s):
            if url not in iocs['urls']:
                iocs['urls'].append(url)

        # Emails
        for email in email_pattern.findall(s):
            if email not in iocs['emails']:
                iocs['emails'].append(email)

        # Domains (excluding common Windows ones)
        skip_domains = ['microsoft.com', 'windows.com', 'localhost',
                        'example.com', 'schemas.microsoft.com']
        for domain in domain_pattern.findall(s):
            if (domain not in iocs['domains'] and
                not any(skip in domain.lower() for skip in skip_domains) and
                len(domain) > 5):
                iocs['domains'].append(domain)

    # Remove duplicates and limit
    for key in iocs:
        iocs[key] = list(set(iocs[key]))[:20]

    return iocs


def check_suspicious_apis(strings_list):
    """
    Look through extracted strings and find any suspicious
    Windows API function names. These indicate what the malware
    is trying to do.
    """
    found = {}
    strings_combined = ' '.join(strings_list)

    for api, description in SUSPICIOUS_APIS.items():
        if api in strings_combined:
            found[api] = description

    return found


def check_malware_families(strings_list):
    """
    Check for indicators of specific malware families.
    """
    text = ' '.join(strings_list).lower()
    indicators = {
        'ransomware' : [],
        'rat_trojan' : [],
    }

    for indicator in RANSOMWARE_INDICATORS:
        if indicator.lower() in text:
            indicators['ransomware'].append(indicator)

    for indicator in RAT_INDICATORS:
        if indicator.lower() in text:
            indicators['rat_trojan'].append(indicator)

    return indicators


def analyze_pe_file(file_path):
    """
    If the file is a Windows EXE or DLL, analyze its PE structure.
    PE = Portable Executable = Windows program format.
    This gives us deep info about what the program does.
    """
    if not PEFILE_AVAILABLE:
        return {'error': 'pefile not installed'}

    try:
        pe = pefile.PE(file_path)
        result = {}

        # Basic PE info
        result['machine_type'] = hex(pe.FILE_HEADER.Machine)
        result['timestamp']    = pe.FILE_HEADER.TimeDateStamp
        result['is_dll']       = bool(pe.FILE_HEADER.Characteristics & 0x2000)
        result['is_exe']       = bool(pe.FILE_HEADER.Characteristics & 0x0002)

        # Sections (parts of the executable)
        sections = []
        for section in pe.sections:
            name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            sections.append({
                'name'    : name,
                'size'    : section.SizeOfRawData,
                'entropy' : round(section.get_entropy(), 2)
                # High entropy (>7.0) = packed/encrypted = suspicious
            })
        result['sections'] = sections

        # High entropy sections mean file might be packed
        high_entropy = [s for s in sections if s['entropy'] > 7.0]
        if high_entropy:
            result['packing_suspected'] = True
            result['packing_note'] = f"{len(high_entropy)} section(s) have high entropy — file may be packed or encrypted"
        else:
            result['packing_suspected'] = False

        # Imported DLLs and functions (what the program uses)
        imports = {}
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                funcs    = []
                for imp in entry.imports:
                    if imp.name:
                        funcs.append(imp.name.decode('utf-8', errors='ignore'))
                imports[dll_name] = funcs[:10]  # limit to 10 per DLL
        result['imports'] = imports

        pe.close()
        return result

    except Exception as e:
        return {'error': f'PE analysis failed: {str(e)}'}


def calculate_entropy(file_path):
    """
    Shannon entropy tells us how random/compressed the data is.
    Normal files: 4-6
    Compressed/encrypted files: 7-8
    High entropy is a sign of packing or encryption.
    """
    try:
        import math
        with open(file_path, 'rb') as f:
            data = f.read()

        if not data:
            return 0

        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1

        entropy = 0
        length  = len(data)
        for count in byte_counts:
            if count > 0:
                prob     = count / length
                entropy -= prob * math.log2(prob)

        return round(entropy, 2)

    except Exception:
        return 0


def run_static_analysis(file_path):
    """
    MAIN FUNCTION — runs all static analysis steps on a file.
    This is what app.py calls.
    """
    if not os.path.exists(file_path):
        return {'error': 'File not found'}

    filename  = os.path.basename(file_path)
    extension = filename.rsplit('.', 1)[-1].lower() if '.' in filename else 'unknown'
    file_size = os.path.getsize(file_path)

    result = {
        'filename'  : filename,
        'extension' : extension,
        'file_size' : f'{round(file_size / 1024, 2)} KB',
        'scan_type' : 'Static Malware Analysis'
    }

    # Step 1 - Real file type
    result['detected_type'] = get_file_type(file_path)

    # Extension mismatch check
    ext_type_map = {
        'pdf': 'PDF', 'exe': 'EXE', 'dll': 'DLL',
        'docx': 'ZIP', 'doc': 'Old Office'
    }
    result['extension_mismatch'] = False
    if extension in ext_type_map:
        expected = ext_type_map[extension]
        if expected.lower() not in result['detected_type'].lower():
            result['extension_mismatch'] = True
            result['mismatch_warning'] = (
                f"File claims to be .{extension} but detected as "
                f"{result['detected_type']} — HIGH SUSPICION"
            )

    # Step 2 - File entropy
    result['entropy'] = calculate_entropy(file_path)
    result['high_entropy'] = result['entropy'] > 7.5

    # Step 3 - Extract strings
    all_strings = extract_strings(file_path)
    result['total_strings'] = len(all_strings)
    result['sample_strings'] = all_strings[:15]

    # Step 4 - Network IOCs from strings
    result['network_iocs'] = extract_network_iocs(all_strings)

    # Step 5 - Suspicious API calls
    result['suspicious_apis'] = check_suspicious_apis(all_strings)

    # Step 6 - Malware family indicators
    result['malware_indicators'] = check_malware_families(all_strings)

    # Step 7 - PE analysis if it's an executable
    if extension in ['exe', 'dll'] or 'EXE' in result['detected_type']:
        result['pe_analysis'] = analyze_pe_file(file_path)

    # Calculate overall threat score
    score   = 0
    reasons = []

    if result['extension_mismatch']:
        score += 3
        reasons.append(result.get('mismatch_warning', 'Extension mismatch detected'))

    if result['high_entropy']:
        score += 3
        reasons.append(f'High file entropy ({result["entropy"]}) — may be packed or encrypted')

    if result['suspicious_apis']:
        score += len(result['suspicious_apis']) * 2
        api_names = list(result['suspicious_apis'].keys())[:3]
        reasons.append(f'Suspicious API calls found: {", ".join(api_names)}')

    if result['malware_indicators']['ransomware']:
        score += 5
        reasons.append('Ransomware indicators detected!')

    if result['malware_indicators']['rat_trojan']:
        score += 4
        reasons.append('RAT/Trojan indicators detected!')

    if result['network_iocs']['ips']:
        score += 2
        reasons.append(f"Hardcoded IPs found: {', '.join(result['network_iocs']['ips'][:2])}")

    if result['network_iocs']['urls']:
        score += 2
        reasons.append(f"Embedded URLs found: {result['network_iocs']['urls'][0][:50]}")

    result['threat_score'] = score
    result['reasons']      = reasons

    if score >= 12:
        result['verdict']     = 'MALICIOUS'
        result['is_phishing'] = True
        result['confidence']  = min(97, 50 + score * 3)
    elif score >= 7:
        result['verdict']     = 'SUSPICIOUS'
        result['is_phishing'] = True
        result['confidence']  = min(75, 35 + score * 4)
    else:
        result['verdict']     = 'CLEAN'
        result['is_phishing'] = False
        result['confidence']  = max(60, 90 - score * 5)

    return result