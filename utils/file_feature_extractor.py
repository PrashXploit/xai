"""
file_feature_extractor.py
Extracts malware-detection features from real uploaded files:
  - EXE / DLL  → PE header analysis via pefile
  - APK        → ZIP-based manifest + entropy analysis
  - Any binary → entropy, size, byte statistics
Returns a single-row DataFrame matching the malware model's feature set.
"""

import io
import math
import hashlib
import zipfile
import numpy as np
import pandas as pd

# ── Expected feature names (must match malware_model training) ──────────────
MALWARE_FEATURES = [
    'file_entropy', 'api_CreateRemoteThread', 'api_VirtualAllocEx',
    'api_SetWindowsHookEx', 'api_InternetConnect', 'api_CryptAcquireContext',
    'suspicious_packing', 'SizeOfCode', 'AddressOfEntryPoint',
    'SectionsMeanEntropy', 'ImportsNbDLL', 'ImportsNb',
    'ResourcesNb', 'Characteristics', 'DllCharacteristics'
]

# Suspicious API strings to scan for in binaries
_SUSPICIOUS_APIS = {
    'api_CreateRemoteThread': b'CreateRemoteThread',
    'api_VirtualAllocEx':     b'VirtualAllocEx',
    'api_SetWindowsHookEx':   b'SetWindowsHookEx',
    'api_InternetConnect':    b'InternetConnect',
    'api_CryptAcquireContext':b'CryptAcquireContext',
}


def _shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    freq = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    prob = freq[freq > 0] / len(data)
    return float(-np.sum(prob * np.log2(prob)))


def _scan_apis(data: bytes) -> dict:
    """Scan raw bytes for suspicious API name strings."""
    return {key: 1.0 if pattern in data else 0.0
            for key, pattern in _SUSPICIOUS_APIS.items()}


def _zero_row() -> dict:
    return {f: 0.0 for f in MALWARE_FEATURES}


# ── PE (EXE / DLL) ──────────────────────────────────────────────────────────
def _extract_pe_features(data: bytes) -> dict:
    row = _zero_row()
    row['file_entropy'] = _shannon_entropy(data)
    row.update(_scan_apis(data))

    try:
        import pefile
        pe = pefile.PE(data=data, fast_load=False)

        opt = pe.OPTIONAL_HEADER
        row['SizeOfCode']          = float(getattr(opt, 'SizeOfCode', 0))
        row['AddressOfEntryPoint'] = float(getattr(opt, 'AddressOfEntryPoint', 0))
        row['Characteristics']     = float(getattr(pe.FILE_HEADER, 'Characteristics', 0))
        row['DllCharacteristics']  = float(getattr(opt, 'DllCharacteristics', 0))

        # Section mean entropy
        if pe.sections:
            entropies = [s.get_entropy() for s in pe.sections]
            row['SectionsMeanEntropy'] = float(np.mean(entropies))
        row['ResourcesNb'] = float(
            len(pe.DIRECTORY_ENTRY_RESOURCE.entries)
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') else 0
        )

        # Imports
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            imports = pe.DIRECTORY_ENTRY_IMPORT
            row['ImportsNbDLL'] = float(len(imports))
            row['ImportsNb']    = float(sum(
                len(e.imports) for e in imports
            ))

    except Exception:
        # pefile not installed or parse failed – use heuristics only
        row['SizeOfCode'] = float(len(data))

    # Packing heuristic: high entropy + small import count
    row['suspicious_packing'] = 1.0 if (
        row['file_entropy'] > 6.8 and row['ImportsNbDLL'] < 5
    ) else 0.0

    return row


# ── APK ─────────────────────────────────────────────────────────────────────
def _extract_apk_features(data: bytes) -> dict:
    row = _zero_row()
    row['file_entropy'] = _shannon_entropy(data)
    row.update(_scan_apis(data))

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()
            row['ResourcesNb'] = float(
                sum(1 for n in names if n.startswith('res/'))
            )

            # Read classes.dex for API usage heuristics
            dex_names = [n for n in names if n.endswith('.dex')]
            row['ImportsNbDLL'] = float(len(dex_names))

            dex_bytes = b''
            for dex in dex_names[:3]:              # cap to 3 dex files
                dex_bytes += zf.read(dex)

            if dex_bytes:
                row.update(_scan_apis(dex_bytes))
                row['ImportsNb'] = float(len(dex_bytes) // 512)  # rough estimate
                row['SectionsMeanEntropy'] = _shannon_entropy(dex_bytes)

            # Manifest check
            if 'AndroidManifest.xml' in names:
                manifest = zf.read('AndroidManifest.xml')
                row['SizeOfCode'] = float(len(manifest))
                # Dangerous permission heuristic
                dangerous = [
                    b'SEND_SMS', b'READ_CONTACTS', b'RECORD_AUDIO',
                    b'CAMERA', b'READ_CALL_LOG', b'GET_ACCOUNTS'
                ]
                row['api_InternetConnect'] = float(
                    any(p in manifest for p in dangerous)
                )
    except Exception:
        row['SizeOfCode'] = float(len(data))

    row['suspicious_packing'] = 1.0 if row['file_entropy'] > 7.0 else 0.0
    return row


# ── Generic binary ───────────────────────────────────────────────────────────
def _extract_generic_features(data: bytes) -> dict:
    row = _zero_row()
    row['file_entropy'] = _shannon_entropy(data)
    row.update(_scan_apis(data))
    row['SizeOfCode']          = float(len(data))
    row['SectionsMeanEntropy'] = row['file_entropy']
    row['suspicious_packing']  = 1.0 if row['file_entropy'] > 6.8 else 0.0
    return row


# ── Public API ───────────────────────────────────────────────────────────────
def extract_features_from_file(file_bytes: bytes, filename: str) -> pd.DataFrame:
    """
    Given raw file bytes and the original filename, return a single-row
    DataFrame with all MALWARE_FEATURES extracted.
    """
    ext = filename.lower().rsplit('.', 1)[-1] if '.' in filename else ''

    if ext in ('exe', 'dll', 'sys', 'scr', 'ocx', 'drv', 'com'):
        row = _extract_pe_features(file_bytes)
        file_type = 'PE Executable'
    elif ext == 'apk':
        row = _extract_apk_features(file_bytes)
        file_type = 'Android APK'
    elif ext in ('zip', 'jar', 'war', 'aar'):
        row = _extract_apk_features(file_bytes)   # same ZIP internals
        file_type = 'Archive/JAR'
    else:
        row = _extract_generic_features(file_bytes)
        file_type = 'Binary File'

    df = pd.DataFrame([row], columns=MALWARE_FEATURES)
    return df, file_type


def get_file_info(file_bytes: bytes, filename: str) -> dict:
    """Return metadata about the uploaded file."""
    return {
        'filename': filename,
        'size_bytes': len(file_bytes),
        'size_kb':    round(len(file_bytes) / 1024, 2),
        'md5':        hashlib.md5(file_bytes).hexdigest(),
        'sha256':     hashlib.sha256(file_bytes).hexdigest()[:32] + '...',
        'entropy':    round(_shannon_entropy(file_bytes), 4),
    }
