"""
Generate realistic sample IDS and Malware CSV datasets for XAI-Sec testing.
Run: python datasets/generate_datasets.py
"""
import numpy as np
import pandas as pd
import os

np.random.seed(42)
OUTPUT_DIR = os.path.dirname(__file__)

# ─────────────────────────────────────────────
# 1. IDS DATASET  (NSL-KDD style, numeric-only)
# ─────────────────────────────────────────────
def generate_ids_dataset(n=1000, filepath=None):
    feature_names = [
        'duration', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment',
        'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised',
        'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
        'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
        'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
        'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
        'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
        'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
        'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
        'dst_host_serror_rate', 'dst_host_srv_serror_rate',
        'dst_host_rerror_rate', 'dst_host_srv_rerror_rate',
        'protocol_type', 'service', 'flag'
    ]

    rows, labels = [], []
    per_class = n // 5

    for label, count in enumerate([per_class]*5):
        for _ in range(count):
            r = {f: 0.0 for f in feature_names}
            r['protocol_type'] = np.random.choice([6, 17, 1])   # tcp=6, udp=17, icmp=1
            r['service']       = np.random.randint(0, 70)        # encoded port group
            r['flag']          = np.random.randint(0, 11)        # encoded flag

            if label == 0:   # Normal
                r['src_bytes']     = np.abs(np.random.normal(250, 50))
                r['dst_bytes']     = np.abs(np.random.normal(3000, 800))
                r['logged_in']     = 1.0
                r['count']         = np.abs(np.random.normal(5, 2))
                r['same_srv_rate'] = np.clip(np.random.normal(0.95, 0.05), 0, 1)
                r['serror_rate']   = np.clip(np.random.normal(0.01, 0.01), 0, 1)
            elif label == 1: # DoS
                r['src_bytes']   = np.abs(np.random.normal(1100, 200))
                r['dst_bytes']   = 0.0
                r['count']       = np.abs(np.random.normal(220, 50))
                r['serror_rate'] = np.clip(np.random.normal(0.95, 0.04), 0, 1)
                r['logged_in']   = 0.0
            elif label == 2: # Probe
                r['src_bytes']      = np.abs(np.random.normal(22, 5))
                r['dst_bytes']      = np.abs(np.random.normal(18, 5))
                r['count']          = np.abs(np.random.normal(55, 10))
                r['diff_srv_rate']  = np.clip(np.random.normal(0.88, 0.08), 0, 1)
            elif label == 3: # R2L
                r['src_bytes']        = np.abs(np.random.normal(310, 100))
                r['dst_bytes']        = np.abs(np.random.normal(5200, 2000))
                r['num_failed_logins']= np.abs(np.random.normal(3, 1))
                r['is_guest_login']   = 1.0
            elif label == 4: # U2R
                r['src_bytes']           = np.abs(np.random.normal(150, 40))
                r['root_shell']          = 1.0
                r['num_file_creations']  = np.abs(np.random.normal(2, 0.8))
                r['su_attempted']        = 1.0

            rows.append([r[f] for f in feature_names])
            labels.append(label)

    df = pd.DataFrame(rows, columns=feature_names)
    df['label'] = labels          # 0=Normal,1=DoS,2=Probe,3=R2L,4=U2R
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    if filepath is None:
        filepath = os.path.join(OUTPUT_DIR, 'ids_dataset.csv')
    df.to_csv(filepath, index=False)
    print(f"✅ IDS dataset saved → {filepath}  ({len(df)} rows, label dist: {df['label'].value_counts().to_dict()})")
    return df


# ─────────────────────────────────────────────
# 2. MALWARE DATASET  (PE-header / API style)
# ─────────────────────────────────────────────
def generate_malware_dataset(n=1000, filepath=None):
    feature_names = [
        'file_entropy', 'api_CreateRemoteThread', 'api_VirtualAllocEx',
        'api_SetWindowsHookEx', 'api_InternetConnect', 'api_CryptAcquireContext',
        'suspicious_packing', 'SizeOfCode', 'AddressOfEntryPoint',
        'SectionsMeanEntropy', 'ImportsNbDLL', 'ImportsNb',
        'ResourcesNb', 'Characteristics', 'DllCharacteristics'
    ]

    rows, labels = [], []
    half = n // 2

    for label, count in [(0, half), (1, n - half)]:
        for _ in range(count):
            if label == 0:   # Benign
                r = {
                    'file_entropy':          np.clip(np.random.normal(4.5, 0.8), 0, 8),
                    'api_CreateRemoteThread':0.0,
                    'api_VirtualAllocEx':    0.0,
                    'api_SetWindowsHookEx':  0.0,
                    'api_InternetConnect':   float(np.random.rand() > 0.5),
                    'api_CryptAcquireContext':float(np.random.rand() > 0.8),
                    'suspicious_packing':    0.0,
                    'SizeOfCode':            np.abs(np.random.normal(52000, 20000)),
                    'AddressOfEntryPoint':   np.abs(np.random.normal(4100, 900)),
                    'SectionsMeanEntropy':   np.clip(np.random.normal(4.0, 0.5), 0, 8),
                    'ImportsNbDLL':          np.abs(np.random.normal(8, 2)),
                    'ImportsNb':             np.abs(np.random.normal(155, 45)),
                    'ResourcesNb':           np.abs(np.random.normal(10, 4)),
                    'Characteristics':       258.0,
                    'DllCharacteristics':    33088.0,
                }
            else:            # Malware
                entropy = np.clip(np.random.normal(7.2, 0.4), 5.5, 8.0)
                r = {
                    'file_entropy':           entropy,
                    'api_CreateRemoteThread': float(np.random.rand() > 0.2),
                    'api_VirtualAllocEx':     float(np.random.rand() > 0.3),
                    'api_SetWindowsHookEx':   float(np.random.rand() > 0.6),
                    'api_InternetConnect':    float(np.random.rand() > 0.2),
                    'api_CryptAcquireContext':float(np.random.rand() > 0.5),
                    'suspicious_packing':     float(entropy > 6.8),
                    'SizeOfCode':             np.abs(np.random.normal(9500, 4000)),
                    'AddressOfEntryPoint':    np.abs(np.random.normal(21000, 4500)),
                    'SectionsMeanEntropy':    np.clip(np.random.normal(6.8, 0.5), 0, 8),
                    'ImportsNbDLL':           max(1, np.abs(np.random.normal(3, 1))),
                    'ImportsNb':              np.abs(np.random.normal(18, 8)),
                    'ResourcesNb':            np.abs(np.random.normal(3, 1.5)),
                    'Characteristics':        33167.0,
                    'DllCharacteristics':     0.0,
                }

            rows.append([r[f] for f in feature_names])
            labels.append(label)

    df = pd.DataFrame(rows, columns=feature_names)
    df['label'] = labels          # 0=Clean, 1=Malware
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    if filepath is None:
        filepath = os.path.join(OUTPUT_DIR, 'malware_dataset.csv')
    df.to_csv(filepath, index=False)
    print(f"✅ Malware dataset saved → {filepath}  ({len(df)} rows, label dist: {df['label'].value_counts().to_dict()})")
    return df


if __name__ == '__main__':
    generate_ids_dataset(n=1000)
    generate_malware_dataset(n=1000)
    print("\n🎉 Both datasets generated successfully in datasets/")
