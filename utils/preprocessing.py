import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

IDS_FEATURE_NAMES = [
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

MALWARE_FEATURE_NAMES = [
    'file_entropy', 'api_CreateRemoteThread', 'api_VirtualAllocEx',
    'api_SetWindowsHookEx', 'api_InternetConnect', 'api_CryptAcquireContext',
    'suspicious_packing', 'SizeOfCode', 'AddressOfEntryPoint',
    'SectionsMeanEntropy', 'ImportsNbDLL', 'ImportsNb', 'ResourcesNb',
    'Characteristics', 'DllCharacteristics'
]


def _align_features(X, expected_features):
    X_aligned = pd.DataFrame(index=X.index)
    for col in expected_features:
        if col in X.columns:
            X_aligned[col] = X[col]
        else:
            X_aligned[col] = 0.0
    return X_aligned


def _map_attack_label(value):
    """Convert KDD attack names to numeric IDS class labels."""
    if pd.isna(value):
        return 0
    s = str(value).strip().lower()
    mapping = {
        'normal': 0,
        'dos': 1,
        'probe': 2,
        'r2l': 3,
        'u2r': 4,
        'neptune': 1,
        'smurf': 1,
        'back': 1,
        'teardrop': 1,
        'pod': 1,
        'land': 1,
        'apache2': 1,
        'udpstorm': 1,
        'processtable': 1,
        'mailbomb': 1,
        'satan': 2,
        'ipsweep': 2,
        'nmap': 2,
        'portsweep': 2,
        'saint': 2,
        'mscan': 2,
        'guess_passwd': 3,
        'ftp_write': 3,
        'imap': 3,
        'phf': 3,
        'multihop': 3,
        'warezmaster': 3,
        'warezclient': 3,
        'spy': 3,
        'named': 3,
        'snmpguess': 3,
        'worm': 3,
        'xlock': 3,
        'xsnoop': 3,
        'sendmail': 3,
        'httptunnel': 3,
        'buffer_overflow': 4,
        'loadmodule': 4,
        'perl': 4,
        'rootkit': 4,
        'snmpgetattack': 3,
        'ps': 3,
        'sqlattack': 4,
        'xterm': 4,
        'httptunnel': 3,
    }
    return int(mapping.get(s, 0))


def _load_real_ids_dataset(train_mode: bool = True):
    candidates = [
        PROJECT_ROOT / 'datasets' / 'ids_dataset' / ('KDDTrain+.txt' if train_mode else 'KDDTest+.txt'),
        PROJECT_ROOT / 'datasets' / 'ids_dataset.csv',
        PROJECT_ROOT / 'datasets' / 'ids_dataset' / 'KDDTrain+.csv',
        PROJECT_ROOT / 'datasets' / 'ids_dataset' / 'KDDTest+.csv',
    ]

    for path in candidates:
        if not path.exists():
            continue

        if path.suffix.lower() == '.txt':
            df = pd.read_csv(path, header=None)
            if df.shape[1] >= len(IDS_FEATURE_NAMES) + 1:
                cols = IDS_FEATURE_NAMES + ['label']
                df = df.iloc[:, :len(cols)]
                df.columns = cols
            else:
                df.columns = [f'feature_{i}' for i in range(df.shape[1])]
                if 'label' not in df.columns:
                    df['label'] = 0
        else:
            df = pd.read_csv(path)

        if 'label' in df.columns:
            y = df['label'].copy()
            X = df.drop(columns=['label'])
            if X.select_dtypes(include=['object']).columns.size:
                X = pd.get_dummies(X)
            if y.dtype == 'object':
                y = y.map(_map_attack_label).astype(int)
            elif not pd.api.types.is_integer_dtype(y):
                y = pd.Series(y).map(_map_attack_label).astype(int)
            return X, y.astype(int)

        if 'class' in df.columns:
            df = df.rename(columns={'class': 'label'})
            y = df['label'].copy()
            X = df.drop(columns=['label'])
            if X.select_dtypes(include=['object']).columns.size:
                X = pd.get_dummies(X)
            if y.dtype == 'object':
                y = y.map(_map_attack_label).astype(int)
            return X, y.astype(int)

    return None


def _load_real_malware_dataset():
    candidates = [
        PROJECT_ROOT / 'datasets' / 'malware_dataset.csv',
        PROJECT_ROOT / 'datasets' / 'malware_dataset' / 'malware_dataset.csv',
    ]

    for path in candidates:
        if not path.exists():
            continue

        df = pd.read_csv(path)
        if 'label' in df.columns:
            y = df['label'].copy()
            X = df.drop(columns=['label'], errors='ignore')
            X = X.drop(columns=['Name', 'md5'], errors='ignore')
            return X, y.astype(int)

    return None


def get_ids_data(filepath=None, is_training=True, expected_features=None):
    if filepath and str(filepath).endswith('.csv'):
        df = pd.read_csv(filepath)
        target_col = [c for c in df.columns if 'class' in c.lower() or 'label' in c.lower() or 'target' in c.lower() or 'attack' in c.lower()]

        if len(target_col) > 0:
            y = df[target_col[0]]
            X = df.drop(columns=[target_col[0]], errors='ignore')
            if y.dtype == 'object':
                mapping = {'normal': 0, 'dos': 1, 'probe': 2, 'r2l': 3, 'u2r': 4}
                y = y.str.lower().map(mapping).fillna(1)
            y = y.astype(int)
        else:
            y = pd.Series([0] * len(df), name='label')
            X = df.copy()

        X = pd.get_dummies(X)
    else:
        real_data = _load_real_ids_dataset(train_mode=is_training)
        if real_data is not None:
            X, y = real_data
        else:
            n_samples = 1500 if is_training else 500
            np.random.seed(42 if is_training else 100)

            X_data = []
            y_data = []

            for _ in range(n_samples):
                label = np.random.choice([0, 1, 2, 3, 4], p=[0.6, 0.2, 0.1, 0.05, 0.05])
                y_data.append(label)

                row = {col: 0.0 for col in IDS_FEATURE_NAMES}

                if label == 0:
                    row['src_bytes'] = np.abs(np.random.normal(250, 50))
                    row['dst_bytes'] = np.abs(np.random.normal(3000, 1000))
                    row['logged_in'] = 1.0 if np.random.rand() > 0.1 else 0.0
                    row['count'] = np.abs(np.random.normal(5, 2))
                    row['same_srv_rate'] = np.clip(np.random.normal(0.95, 0.05), 0, 1)
                elif label == 1:
                    row['src_bytes'] = np.abs(np.random.normal(1000, 200))
                    row['dst_bytes'] = 0.0
                    row['count'] = np.abs(np.random.normal(200, 50))
                    row['serror_rate'] = np.clip(np.random.normal(0.95, 0.05), 0, 1)
                elif label == 2:
                    row['src_bytes'] = np.abs(np.random.normal(20, 5))
                    row['dst_bytes'] = np.abs(np.random.normal(20, 5))
                    row['count'] = np.abs(np.random.normal(50, 10))
                    row['diff_srv_rate'] = np.clip(np.random.normal(0.9, 0.1), 0, 1)
                elif label == 3:
                    row['src_bytes'] = np.abs(np.random.normal(300, 100))
                    row['dst_bytes'] = np.abs(np.random.normal(5000, 2000))
                    row['num_failed_logins'] = np.abs(np.random.normal(3, 1))
                    row['is_guest_login'] = 1.0 if np.random.rand() > 0.2 else 0.0
                elif label == 4:
                    row['src_bytes'] = np.abs(np.random.normal(150, 50))
                    row['dst_bytes'] = np.abs(np.random.normal(400, 100))
                    row['root_shell'] = 1.0
                    row['num_file_creations'] = np.abs(np.random.normal(2, 1))

                X_data.append([row[col] for col in IDS_FEATURE_NAMES])

            X = pd.DataFrame(X_data, columns=IDS_FEATURE_NAMES)
            y = pd.Series(y_data, name='label')

    if expected_features is not None:
        X = _align_features(X, expected_features)

    return X, y


def get_malware_data(filepath=None, is_training=True, expected_features=None):
    if filepath and str(filepath).endswith('.csv'):
        df = pd.read_csv(filepath)
        target_col = [c for c in df.columns if 'class' in c.lower() or 'label' in c.lower() or 'target' in c.lower() or 'legitimate' in c.lower() or 'malware' in c.lower()]

        if len(target_col) > 0:
            y = df[target_col[0]]
            X = df.drop(columns=[target_col[0], 'Name', 'md5'], errors='ignore')
        else:
            y = pd.Series([0] * len(df), name='label')
            X = df.drop(columns=['Name', 'md5'], errors='ignore')

        X = pd.get_dummies(X)
    else:
        real_data = _load_real_malware_dataset()
        if real_data is not None:
            X, y = real_data
        else:
            n_samples = 1000 if is_training else 500
            np.random.seed(42 if is_training else 100)

            X_data = []
            y_data = []

            for _ in range(n_samples):
                label = np.random.choice([0, 1], p=[0.5, 0.5])
                y_data.append(label)

                row = {}
                if label == 0:
                    row['file_entropy'] = np.random.normal(4.5, 0.8)
                    row['api_CreateRemoteThread'] = 0.0
                    row['api_VirtualAllocEx'] = 0.0
                    row['api_SetWindowsHookEx'] = 0.0
                    row['api_InternetConnect'] = 1.0 if np.random.rand() > 0.5 else 0.0
                    row['api_CryptAcquireContext'] = 1.0 if np.random.rand() > 0.8 else 0.0
                    row['suspicious_packing'] = 0.0
                    row['SizeOfCode'] = np.abs(np.random.normal(50000, 20000))
                    row['AddressOfEntryPoint'] = np.abs(np.random.normal(4000, 1000))
                    row['SectionsMeanEntropy'] = np.random.normal(4.0, 0.5)
                    row['ImportsNbDLL'] = np.abs(np.random.normal(8, 3))
                    row['ImportsNb'] = np.abs(np.random.normal(150, 50))
                    row['ResourcesNb'] = np.abs(np.random.normal(10, 5))
                    row['Characteristics'] = 258
                    row['DllCharacteristics'] = 33088
                else:
                    row['file_entropy'] = np.clip(np.random.normal(7.2, 0.5), 0, 8.0)
                    row['api_CreateRemoteThread'] = 1.0 if np.random.rand() > 0.2 else 0.0
                    row['api_VirtualAllocEx'] = 1.0 if np.random.rand() > 0.3 else 0.0
                    row['api_SetWindowsHookEx'] = 1.0 if np.random.rand() > 0.6 else 0.0
                    row['api_InternetConnect'] = 1.0 if np.random.rand() > 0.2 else 0.0
                    row['api_CryptAcquireContext'] = 1.0 if np.random.rand() > 0.5 else 0.0
                    row['suspicious_packing'] = 1.0 if row['file_entropy'] > 6.8 else 0.0
                    row['SizeOfCode'] = np.abs(np.random.normal(10000, 5000))
                    row['AddressOfEntryPoint'] = np.abs(np.random.normal(20000, 5000))
                    row['SectionsMeanEntropy'] = np.clip(np.random.normal(6.8, 0.6), 0, 8)
                    row['ImportsNbDLL'] = np.abs(np.random.normal(3, 1))
                    row['ImportsNb'] = np.abs(np.random.normal(20, 10))
                    row['ResourcesNb'] = np.abs(np.random.normal(3, 2))
                    row['Characteristics'] = 33167
                    row['DllCharacteristics'] = 0

                X_data.append([row[col] for col in MALWARE_FEATURE_NAMES])

            X = pd.DataFrame(X_data, columns=MALWARE_FEATURE_NAMES)
            y = pd.Series(y_data, name='label')

    if expected_features is not None:
        X = _align_features(X, expected_features)

    return X, y


def split_data(X, y):
    return train_test_split(X, y, test_size=0.2, random_state=42)
