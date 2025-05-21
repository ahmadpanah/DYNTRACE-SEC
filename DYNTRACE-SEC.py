import numpy as np
from sklearn.cluster import AffinityPropagation
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from collections import Counter, defaultdict
import random
import time
import math
import docker
import kubernetes.client
import kubernetes.config
from kubernetes.client.rest import ApiException

# --- 1. Constants and Configuration ---

AP_DAMPING = 0.9
LOAD_SENSITIVITY_FACTOR = 0.3

TRUST_WEIGHTS = {
    'cohesion': 0.3,
    'anomaly': 0.3,
    'vuln': 0.2,
    'hist': 0.15,
    'age': 0.05
}

HIST_DECAY_RATE = 0.95

RISK_PROFILE = {
    'critical_TS_threshold': 0.3,
    'high_TS_threshold': 0.85,
    'moderate_TS_threshold': 0.5,
    'trust_gap_alert_thresh': 0.4,
    'base_log_level': 1,
    'max_bps': 1000,
    'sensitive_protocols': ['http', 'mysql', 'postgres', 'ssh'],
    'profile_sensitivity': 1.5
}

# --- 2. Container Representation & Syscall Simulation ---

class Container:
    def __init__(self, container_id, container_name, container_type, is_malicious=False,
                 pod_name=None, namespace=None, labels=None):
        self.id = container_id
        self.name = container_name
        self.type = container_type  # Derived type like 'webserver', 'database'
        self.is_malicious = is_malicious
        self.syscall_sequence = []
        self.current_anomaly_score = 0.0
        self.vulnerability_score = 0.0
        self.segment_id = None

        # Kubernetes specific attributes
        self.pod_name = pod_name
        self.namespace = namespace
        self.labels = labels if labels is not None else {}

    def __repr__(self):
        return (f"Container(ID={self.id}, Name={self.name}, Type={self.type}, "
                f"Malicious={self.is_malicious}, Segment={self.segment_id}, "
                f"Pod={self.pod_name}/{self.namespace})")

class SyscallGenerator:
    # Syscall sets based on common container types
    BENIGN_SYSCALLS = {
        'webserver': ['recvfrom', 'sendto', 'open', 'read', 'close', 'mmap', 'epoll_wait', 'fcntl', 'stat', 'access'],
        'database': ['read', 'write', 'fsync', 'sendmsg', 'recvmsg', 'poll', 'epoll_wait', 'mmap', 'fstat'],
        'cache': ['read', 'write', 'socket', 'bind', 'listen', 'accept', 'close', 'epoll_wait', 'getpeername'],
        'microservice': ['connect', 'sendto', 'recvfrom', 'open', 'read', 'close', 'write', 'futex', 'pipe'],
        'default': ['read', 'write', 'open', 'close', 'stat', 'mmap'] # Fallback for unknown types
    }
    MALICIOUS_SYSCALLS = {
        'reverse_shell': ['socket', 'connect', 'dup2', 'execve', 'fork', 'pipe', 'fcntl', 'getuid'],
        'network_scan': ['socket', 'connect', 'sendto', 'recvfrom', 'close', 'alarm', 'getpeername', 'setsockopt'],
        'data_exfil': ['open', 'read', 'sendto', 'connect', 'write', 'sendfile', 'unlink', 'getdents64'],
        'cryptojacking': ['fork', 'execve', 'brk', 'mmap', 'open', 'read', 'write', 'getrlimit', 'setrlimit', 'sysinfo']
    }

    def generate_syscall_sequence(self, container_type, is_malicious=False, length=50):
        syscall_set = []
        if is_malicious:
            mal_type = random.choice(list(self.MALICIOUS_SYSCALLS.keys()))
            syscall_set.extend(self.MALICIOUS_SYSCALLS[mal_type])
            ben_type_options = list(self.BENIGN_SYSCALLS.keys())
            ben_type = container_type if container_type in ben_type_options else random.choice(ben_type_options)
            syscall_set.extend(self.BENIGN_SYSCALLS.get(ben_type, self.BENIGN_SYSCALLS['default']))
        else:
            syscall_set.extend(self.BENIGN_SYSCALLS.get(container_type, self.BENIGN_SYSCALLS['default']))

        return [random.choice(syscall_set) for _ in range(length)]

# --- 3. Behavioral Profiling Module ---

class BehavioralProfiler:
    def __init__(self, n_gram_range=(1, 3)):
        self.vectorizer = TfidfVectorizer(ngram_range=n_gram_range, token_pattern=r'\b\w+\b', lowercase=False)
        self.container_syscall_data = {}
        self.container_vectors = {}
        self.syscall_gen = SyscallGenerator() # Initialize syscall generator

    def collect_syscalls(self, active_containers):
        """Simulates eBPF collection of syscalls for active containers."""
        print(f"\n[PROFILER] Simulating syscall collection for {len(active_containers)} containers...")
        new_syscall_data = {}
        for c_id, container in active_containers.items():
            if c_id not in self.container_syscall_data or not container.syscall_sequence: # If new or empty
                container.syscall_sequence = self.syscall_gen.generate_syscall_sequence(
                    container.type, container.is_malicious, length=random.randint(50, 100)
                )
            else: # Append new syscalls to existing ones for ongoing activity
                new_syscalls = self.syscall_gen.generate_syscall_sequence(
                    container.type, container.is_malicious, length=random.randint(5, 15)
                )
                container.syscall_sequence.extend(new_syscalls)
                container.syscall_sequence = container.syscall_sequence[-100:] # Keep length manageable

            new_syscall_data[c_id] = container.syscall_sequence
        self.container_syscall_data = new_syscall_data

    def vectorize_behavior(self):
        """Transforms collected syscall sequences into TF-IDF vectors."""
        if not self.container_syscall_data:
            print("[PROFILER] No syscall data to vectorize.")
            return {}

        container_ids = list(self.container_syscall_data.keys())
        corpus = [" ".join(seq) for seq in self.container_syscall_data.values()]

        # Fit and transform the corpus. In a real system, `fit` would occur once
        # on a large corpus, and `transform` would be used subsequently.
        try:
            vectors_sparse = self.vectorizer.fit_transform(corpus)
            self.container_vectors = {
                container_ids[i]: vectors_sparse[i].toarray().flatten()
                for i in range(len(container_ids))
            }
            print(f"[PROFILER] Vectorized behaviors for {len(self.container_vectors)} containers. Vector dim: {vectors_sparse.shape[1]}")
        except ValueError as e:
            print(f"[PROFILER] Error vectorizing: {e}. This often happens if corpus is empty or all documents are identical after filtering.")
            self.container_vectors = {}
        
        return self.container_vectors

# --- 4. DAP-LSP Module ---

class DAP_LSP:
    def __init__(self, damping=AP_DAMPING, load_sensitivity_factor=LOAD_SENSITIVITY_FACTOR):
        self.damping = damping
        self.load_sensitivity_factor = load_sensitivity_factor
        self.current_segments = {}
        self.current_exemplars = {}
        self.segment_creation_times = {}

    def G_target(self, load_idx):
        """Maps current load index to a target range for the number of security segments."""
        if load_idx < 0.3: # Low load
            return (8, 12) # More fine-grained segments
        elif load_idx < 0.7: # Medium load
            return (5, 9)
        else: # High load
            return (3, 6) # Fewer, coarser segments

    def calculate_preferences(self, vectors, load_idx, historical_exemplars):
        """Calculates Affinity Propagation preferences, adjusted for load and historical exemplars."""
        if not vectors:
            return np.array([])

        similarity_matrix = cosine_similarity(list(vectors.values()))
        np.fill_diagonal(similarity_matrix, 0) 
        
        initial_preference = np.median(similarity_matrix[similarity_matrix != 0]) if similarity_matrix.size > 0 else -1.0
        adjusted_preference = initial_preference * (1 - self.load_sensitivity_factor * load_idx)
        preferences = np.full(len(vectors), adjusted_preference)
        
        if historical_exemplars:
            container_ids = list(vectors.keys())
            for i, c_id in enumerate(container_ids):
                current_vec = vectors[c_id]
                for hist_seg_id, hist_exemplar_vec in historical_exemplars.items():
                    if hist_exemplar_vec is not None and len(current_vec) == len(hist_exemplar_vec) and np.linalg.norm(current_vec) > 1e-9: # Avoid zero vector
                        sim = cosine_similarity([current_vec], [hist_exemplar_vec])[0][0]
                        if sim > 0.8:
                            preferences[i] *= 1.1

        return preferences

    def consolidate_segments(self, initial_exemplars, initial_labels, vectors_map, load_idx):
        """Prunes and consolidates segments to align with load-adaptive granularity."""
        container_ids_list = list(vectors_map.keys())
        vectors_list = list(vectors_map.values())
        
        current_exemplars = {
            initial_labels[i]: vectors_list[idx] for i, idx in enumerate(initial_exemplars)
        }
        current_labels = {
            container_ids_list[i]: initial_labels[i] for i in range(len(container_ids_list))
        }

        K_target_min, K_target_max = self.G_target(load_idx)
        print(f"[DAP-LSP] Initial {len(current_exemplars)} segments. Target range: [{K_target_min}, {K_target_max}]")

        while len(current_exemplars) > K_target_max:
            if len(current_exemplars) <= 1:
                break

            exemplar_ids = list(current_exemplars.keys())
            exemplar_vectors = list(current_exemplars.values())
            
            if len(exemplar_vectors) > 1:
                exemplar_similarity_matrix = cosine_similarity(exemplar_vectors)
                np.fill_diagonal(exemplar_similarity_matrix, -1.0)

                max_sim_idx = np.unravel_index(exemplar_similarity_matrix.argmax(), exemplar_similarity_matrix.shape)
                idx1, idx2 = max_sim_idx
                
                seg_id1, seg_id2 = exemplar_ids[idx1], exemplar_ids[idx2]
                
                print(f"  Merging segments {seg_id1} and {seg_id2} (similarity: {exemplar_similarity_matrix[idx1, idx2]:.2f})")

                merged_containers = [cid for cid, seg in current_labels.items() if seg == seg_id1 or seg == seg_id2]
                
                merged_vectors = [vectors_map[cid] for cid in merged_containers]
                new_exemplar = np.mean(merged_vectors, axis=0) if merged_vectors else np.zeros_like(exemplar_vectors[0])

                new_seg_id = max(exemplar_ids) + 1 if exemplar_ids else 0
                
                del current_exemplars[seg_id1]
                del current_exemplars[seg_id2]
                current_exemplars[new_seg_id] = new_exemplar

                for cid in merged_containers:
                    current_labels[cid] = new_seg_id
            else:
                break
        
        print(f"[DAP-LSP] Final {len(current_exemplars)} segments after consolidation.")
        return current_exemplars, current_labels

    def run_clustering(self, container_vectors, current_load_idx, historical_exemplars={}):
        """Orchestrates the DAP-LSP clustering process."""
        if not container_vectors:
            return {}, {}

        container_ids_list = list(container_vectors.keys())
        vectors_list = np.array(list(container_vectors.values()))

        # Remove zero vectors as they can cause issues with cosine similarity and AP
        non_zero_indices = [i for i, v in enumerate(vectors_list) if np.linalg.norm(v) > 1e-9]
        if not non_zero_indices:
            print("[DAP-LSP] No non-zero vectors to cluster. Skipping.")
            return {}, {}

        filtered_vectors_list = vectors_list[non_zero_indices]
        filtered_container_ids = [container_ids_list[i] for i in non_zero_indices]
        filtered_vectors_map = {cid: vectors_map[cid] for cid in filtered_container_ids}

        preferences = self.calculate_preferences(filtered_vectors_map, current_load_idx, historical_exemplars)

        if preferences.size == 0:
            return {}, {}
        
        # Ensure preferences length matches filtered_vectors_list
        if len(preferences) != len(filtered_vectors_list):
            print(f"[DAP-LSP] Mismatch in preferences array size ({len(preferences)}) and vectors size ({len(filtered_vectors_list)}). Adjusting.")
            preferences = preferences[:len(filtered_vectors_list)] # Trim or pad if necessary, ideally fix calculation
            # A more robust fix would be to ensure calculate_preferences operates only on non_zero_vectors from the start.

        ap = AffinityPropagation(
            affinity='cosine',
            damping=self.damping,
            preferences=preferences,
            random_state=42,
            max_iter=500,
            convergence_iter=25
        )
        ap.fit(filtered_vectors_list)

        initial_exemplar_indices = ap.cluster_centers_indices_
        initial_labels = ap.labels_

        # Map initial_exemplar_indices back to original container_vectors keys
        initial_exemplar_container_ids = [filtered_container_ids[idx] for idx in initial_exemplar_indices]

        # Consolidate segments based on load
        final_exemplars_map, final_labels_map = self.consolidate_segments(
            initial_exemplar_indices, initial_labels, filtered_vectors_map, current_load_idx
        )

        segments = defaultdict(list)
        for c_id, seg_id in final_labels_map.items():
            segments[seg_id].append(c_id)
        
        new_segment_creation_times = {}
        current_time = time.time()
        for seg_id in final_exemplars_map.keys():
            if seg_id not in self.segment_creation_times:
                new_segment_creation_times[seg_id] = current_time
            else:
                new_segment_creation_times[seg_id] = self.segment_creation_times[seg_id]
        self.segment_creation_times = new_segment_creation_times

        final_exemplars_corrected = {}
        for seg_id, container_list in segments.items():
            if container_list:
                cluster_vectors = [container_vectors[cid] for cid in container_list if cid in container_vectors]
                if cluster_vectors:
                    final_exemplars_corrected[seg_id] = np.mean(cluster_vectors, axis=0)
                else:
                    final_exemplars_corrected[seg_id] = np.zeros(filtered_vectors_list.shape[1]) # Default to zero vector
            else:
                final_exemplars_corrected[seg_id] = np.zeros(filtered_vectors_list.shape[1])

        return segments, final_exemplars_corrected

# --- 5. TWAPE Component (Trust Score Calculation) ---

class TrustScoreManager:
    def __init__(self, weights=TRUST_WEIGHTS, decay_rate=HIST_DECAY_RATE):
        self.weights = weights
        self.decay_rate = decay_rate
        self.segment_trust_scores = {}
        self.historical_reputation = defaultdict(lambda: 0.8) # Initialize with moderate trust

    def calculate_trust_score(self, segments, container_vectors, containers_map, exemplars, segment_creation_times):
        """Computes and updates a continuous Trust Score for each security segment."""
        print("\n[TWAPE-TSM] Calculating Trust Scores for segments...")
        new_trust_scores = {}
        for seg_id, container_ids in segments.items():
            if not container_ids:
                new_trust_scores[seg_id] = 0.0
                continue

            segment_vectors = [container_vectors[cid] for cid in container_ids if cid in container_vectors]
            segment_exemplar = exemplars.get(seg_id)
            
            score_cohesion = 0.0
            if segment_exemplar is not None and len(segment_vectors) > 0 and len(segment_vectors[0]) == len(segment_exemplar):
                # Filter out zero vectors which can cause nan with cosine similarity (if norm is 0)
                valid_vectors = [v for v in segment_vectors if np.linalg.norm(v) > 1e-9]
                if valid_vectors:
                    similarities = [cosine_similarity([v], [segment_exemplar])[0][0] for v in valid_vectors]
                    score_cohesion = (np.mean(similarities) + 1) / 2 # Scale cosine sim from -1 to 1, to 0 to 1
                else:
                    score_cohesion = 0.1 # No valid vectors, low cohesion
            else:
                score_cohesion = 0.1 

            anomaly_scores = []
            for cid in container_ids:
                container = containers_map.get(cid)
                if container:
                    if container.is_malicious:
                        container.current_anomaly_score = random.uniform(0.7, 1.0)
                    else:
                        container.current_anomaly_score = random.uniform(0.0, 0.2)
                    anomaly_scores.append(container.current_anomaly_score)
            
            max_anomaly_score = max(anomaly_scores) if anomaly_scores else 0.0
            score_anomaly = 1 - max_anomaly_score

            vuln_scores = []
            for cid in container_ids:
                container = containers_map.get(cid)
                if container:
                    if container.is_malicious:
                        container.vulnerability_score = random.uniform(0.8, 1.0)
                    else:
                        container.vulnerability_score = random.uniform(0.0, 0.3)
                    vuln_scores.append(container.vulnerability_score)
            
            max_vuln_score = max(vuln_scores) if vuln_scores else 0.0
            score_vuln = 1 - max_vuln_score

            score_hist = self.historical_reputation[seg_id]

            age = time.time() - segment_creation_times.get(seg_id, time.time())
            score_age = min(age / 1000.0, 1.0) * 0.1

            trust_score = (
                self.weights['cohesion'] * score_cohesion +
                self.weights['anomaly'] * score_anomaly +
                self.weights['vuln'] * score_vuln +
                self.weights['hist'] * score_hist +
                self.weights['age'] * score_age
            )
            
            trust_score = max(0.0, min(1.0, trust_score))
            new_trust_scores[seg_id] = trust_score
            print(f"  Segment {seg_id}: TS={trust_score:.2f} (Cohesion:{score_cohesion:.2f}, Anomaly:{score_anomaly:.2f}, Vuln:{score_vuln:.2f}, Hist:{score_hist:.2f}, Age:{score_age:.2f})")

        self.segment_trust_scores = new_trust_scores
        return self.segment_trust_scores

    def update_historical_reputation(self, segment_id, feedback_value):
        """Updates historical reputation for a segment based on interaction feedback."""
        current_hist = self.historical_reputation[segment_id]
        if feedback_value < 0:
            new_hist = current_hist * (self.decay_rate ** 2) + (1 - (self.decay_rate ** 2)) * (0 if feedback_value == -1 else (0.5 + feedback_value * 0.5))
        else:
            new_hist = current_hist * self.decay_rate + (1 - self.decay_rate) * (0.5 + feedback_value * 0.5)
        
        self.historical_reputation[segment_id] = max(0.0, min(1.0, new_hist))
        print(f"  [TWAPE-TSM] Updated historical reputation for Segment {segment_id} to {self.historical_reputation[segment_id]:.2f} (feedback: {feedback_value})")

# --- 6. TWAPE Core (Policy Engine) ---

class PolicyEngine:
    def __init__(self, risk_profile=RISK_PROFILE):
        self.risk_profile = risk_profile

    def scale_intensity(self, base_val, ts1, ts2):
        """Helper to scale enforcement parameters based on trust scores."""
        avg_ts = (ts1 + ts2) / 2
        risk_factor = (1 - avg_ts) * self.risk_profile['profile_sensitivity']
        return base_val * (1 + risk_factor)

    def get_enforcement_action(self, src_seg_id, dest_seg_id, req_attrs, trust_scores_manager):
        """Determines enforcement action based on trust scores and request attributes."""
        ts_src = trust_scores_manager.segment_trust_scores.get(src_seg_id, 0.5)
        ts_target = trust_scores_manager.segment_trust_scores.get(dest_seg_id, 0.5)

        action = "ALLOW"
        params = {"log_level": 1, "rate_limit_bps": self.risk_profile['max_bps'], "dpi_enabled": False, "alert": "none"}

        print(f"\n[TWAPE-PE] Evaluating communication from Seg {src_seg_id} (TS={ts_src:.2f}) to Seg {dest_seg_id} (TS={ts_target:.2f})")

        if ts_src < self.risk_profile['critical_TS_threshold'] or ts_target < self.risk_profile['critical_TS_threshold']:
            action = "BLOCK"
            params["log_level"] = 5
            params["alert"] = "CRITICAL_LOW_TRUST_INTERACTION"
            params["quarantine_candidate"] = True
        elif ts_src > self.risk_profile['high_TS_threshold'] and ts_target > self.risk_profile['high_TS_threshold']:
            action = "ALLOW"
            params["log_level"] = 1
        else:
            action = "ALLOW_WITH_SCRUTINY"
            params["log_level"] = self.scale_intensity(self.risk_profile['base_log_level'], ts_src, ts_target)
            params["rate_limit_bps"] = self.risk_profile['max_bps'] * min(ts_src, ts_target)
            
            if ts_src < self.risk_profile['moderate_TS_threshold'] and req_attrs.get('protocol') in self.risk_profile['sensitive_protocols']:
                params["dpi_enabled"] = True
                params["log_level"] = max(params["log_level"], 3)
            
            if ts_target - ts_src > self.risk_profile['trust_gap_alert_thresh']:
                 params["alert"] = "MODERATE_RISK_INTERACTION_TRUST_GAP"

        print(f"  Decision: {action}, Parameters: {params}")
        return action, params

# --- 7. Isolation Enforcement Module ---

class EnforcementModule:
    def apply_policy(self, src_container, dest_container, action, params):
        """Simulates the application of security policies. In a real system, this would interact with eBPF, K8s NetworkPolicies, etc."""
        log_msgs = {
            1: "Minimal logging.",
            2: "Standard logging.",
            3: "Increased logging verbosity.",
            4: "Detailed logging.",
            5: "Full context logging, headers."
        }
        
        print(f"[ENFORCER] Applying policy for communication from {src_container.id} (Seg {src_container.segment_id}) to {dest_container.id} (Seg {dest_container.segment_id}):")
        
        if action == "BLOCK":
            print(f"  ACTION: BLOCKED connection. Alert: {params.get('alert', 'N/A')}. Quarantine Candidate: {params.get('quarantine_candidate', False)}")
            print(f"  Logging Level: {params.get('log_level', 'N/A')}. {log_msgs.get(params.get('log_level'), '')}")
            if params.get('alert') == "CRITICAL_LOW_TRUST_INTERACTION":
                print("  CRITICAL: This interaction was highly suspicious and immediately blocked!")
            return False
        elif action == "ALLOW_WITH_SCRUTINY":
            simulated_latency = 0
            if params.get('dpi_enabled'):
                simulated_latency = random.randint(15, 50)
                print(f"  ACTION: ALLOWED_WITH_SCRUTINY. Deep Packet Inspection ENABLED. Simulated Latency: {simulated_latency}µs.")
            else:
                simulated_latency = random.randint(5, 15)
                print(f"  ACTION: ALLOWED_WITH_SCRUTINY. Simulated Latency: {simulated_latency}µs.")
            
            print(f"  Rate Limit: {params.get('rate_limit_bps', 'N/A')} BPS. Alert: {params.get('alert', 'N/A')}.")
            print(f"  Logging Level: {params.get('log_level', 'N/A')}. {log_msgs.get(params.get('log_level'), '')}")
            return True
        elif action == "ALLOW":
            print(f"  ACTION: ALLOWED. Minimal overhead.")
            print(f"  Logging Level: {params.get('log_level', 'N/A')}. {log_msgs.get(params.get('log_level'), '')}")
            return True

# --- 8. DYNTRACE-SEC Controller (Orchestration) ---

class DYNTRACE_SEC_Controller:
    def __init__(self, num_malicious_to_simulate=5, use_kubernetes=True):
        self.profiler = BehavioralProfiler()
        self.dap_lsp = DAP_LSP()
        self.trust_manager = TrustScoreManager()
        self.policy_engine = PolicyEngine()
        self.enforcement_module = EnforcementModule()

        self.containers = {}
        self.segments = {}
        self.exemplars = {}
        self.historical_exemplars = {}
        
        self.use_kubernetes = use_kubernetes
        self.num_malicious_to_simulate = num_malicious_to_simulate

        self._discover_and_initialize_containers()

    def _get_container_type_from_image_or_labels(self, image_name, labels):
        # Basic mapping from image name or labels to a semantic type
        image_name_lower = image_name.lower()
        if 'nginx' in image_name_lower or 'httpd' in image_name_lower or 'web' in labels.get('app', '').lower():
            return 'webserver'
        elif 'postgres' in image_name_lower or 'mysql' in image_name_lower or 'db' in labels.get('app', '').lower():
            return 'database'
        elif 'redis' in image_name_lower or 'memcached' in image_name_lower or 'cache' in labels.get('app', '').lower():
            return 'cache'
        elif 'api' in image_name_lower or 'service' in image_name_lower or 'app' in labels.get('tier', '').lower():
            return 'microservice'
        return 'default'

    def _discover_and_initialize_containers(self):
        print(f"\n--- Discovering containers from {'Kubernetes' if self.use_kubernetes else 'Docker'} ---")
        discovered_containers = []

        if self.use_kubernetes:
            try:
                kubernetes.config.load_kube_config()
                v1 = kubernetes.client.CoreV1Api()
                pods = v1.list_pod_for_all_namespaces(watch=False)
                for pod in pods.items:
                    for container_status in pod.status.container_statuses:
                        if container_status.container_id:
                            # Parse Docker ID from CRI-O format if needed
                            container_id_full = container_status.container_id
                            if container_id_full.startswith("docker://"):
                                container_id = container_id_full[len("docker://"):]
                            elif container_id_full.startswith("containerd://"): # Example for containerd
                                container_id = container_id_full[len("containerd://"):]
                            else:
                                container_id = container_id_full
                            
                            c_type = self._get_container_type_from_image_or_labels(
                                container_status.image, pod.metadata.labels if pod.metadata.labels else {}
                            )
                            discovered_containers.append(
                                Container(
                                    container_id=container_id,
                                    container_name=container_status.name,
                                    container_type=c_type,
                                    pod_name=pod.metadata.name,
                                    namespace=pod.metadata.namespace,
                                    labels=pod.metadata.labels
                                )
                            )
            except kubernetes.config.config_exception.ConfigException:
                print("Kubernetes config not found. Trying in-cluster config...")
                try:
                    kubernetes.config.load_incluster_config()
                    v1 = kubernetes.client.CoreV1Api()
                    pods = v1.list_pod_for_all_namespaces(watch=False)
                    for pod in pods.items:
                        for container_status in pod.status.container_statuses:
                            if container_status.container_id:
                                container_id_full = container_status.container_id
                                if container_id_full.startswith("docker://"):
                                    container_id = container_id_full[len("docker://"):]
                                elif container_id_full.startswith("containerd://"):
                                    container_id = container_id_full[len("containerd://"):]
                                else:
                                    container_id = container_id_full

                                c_type = self._get_container_type_from_image_or_labels(
                                    container_status.image, pod.metadata.labels if pod.metadata.labels else {}
                                )
                                discovered_containers.append(
                                    Container(
                                        container_id=container_id,
                                        container_name=container_status.name,
                                        container_type=c_type,
                                        pod_name=pod.metadata.name,
                                        namespace=pod.metadata.namespace,
                                        labels=pod.metadata.labels
                                    )
                                )
                except kubernetes.config.config_exception.ConfigException as e:
                    print(f"Could not load Kubernetes config: {e}. Falling back to Docker discovery if possible, or using mock data.")
                    self.use_kubernetes = False # Disable K8s for this run
                except ApiException as e:
                    print(f"Kubernetes API Error: {e}. Check RBAC permissions. Falling back to Docker discovery if possible, or using mock data.")
                    self.use_kubernetes = False
            except ApiException as e:
                print(f"Kubernetes API Error: {e}. Check RBAC permissions. Falling back to Docker discovery if possible, or using mock data.")
                self.use_kubernetes = False
        
        if not self.use_kubernetes: # Fallback to Docker if K8s not used or failed
            try:
                client = docker.from_env()
                running_containers = client.containers.list()
                for c in running_containers:
                    c_type = self._get_container_type_from_image_or_labels(
                        c.image.tags[0] if c.image.tags else '', c.labels
                    )
                    discovered_containers.append(
                        Container(c.id, c.name, c_type, labels=c.labels)
                    )
            except Exception as e:
                print(f"Could not connect to Docker daemon: {e}. Using dummy containers for simulation.")
                # If neither Docker nor K8s work, generate dummy containers for the simulation logic to run
                for i in range(50):
                    c_id = f"mock_c{i:03d}"
                    c_type = random.choice(list(SyscallGenerator.BENIGN_SYSCALLS.keys()))
                    discovered_containers.append(Container(c_id, f"mock-container-{i}", c_type))

        if not discovered_containers:
            print("No real containers discovered. Generating 50 dummy containers for simulation.")
            for i in range(50):
                c_id = f"dummy_c{i:03d}"
                c_type = random.choice(list(SyscallGenerator.BENIGN_SYSCALLS.keys()))
                discovered_containers.append(Container(c_id, f"dummy-container-{i}", c_type))
        
        # Randomly mark some containers as "malicious" for simulation purposes
        malicious_candidates = [c for c in discovered_containers if c.type != 'database' and c.type != 'cache'] # Exclude "critical" for random malicious marking
        random.shuffle(malicious_candidates)
        
        num_marked_malicious = 0
        for container in malicious_candidates:
            if num_marked_malicious < self.num_malicious_to_simulate:
                container.is_malicious = True
                num_marked_malicious += 1
            else:
                break
        
        for container in discovered_containers:
            self.containers[container.id] = container
        
        print(f"Total containers for simulation: {len(self.containers)} (Maliciously marked: {num_marked_malicious})")

    def run_profiling_and_segmentation(self, current_load_idx):
        """Executes the behavioral profiling and DAP-LSP segmentation cycle."""
        print("\n--- Running Profiling and Segmentation Cycle ---")
        self.profiler.collect_syscalls(self.containers)
        container_vectors = self.profiler.vectorize_behavior()
        
        if not container_vectors:
            print("[CONTROLLER] No container vectors for segmentation. Skipping.")
            self.segments = {}
            self.exemplars = {}
            return

        new_segments, new_exemplars = self.dap_lsp.run_clustering(
            container_vectors, current_load_idx, self.historical_exemplars
        )
        
        self.segments = new_segments
        self.exemplars = new_exemplars
        
        self.historical_exemplars = new_exemplars
        
        for seg_id, c_ids in self.segments.items():
            for c_id in c_ids:
                if c_id in self.containers:
                    self.containers[c_id].segment_id = seg_id
        
        print(f"Segmentation complete. Total segments: {len(self.segments)}")
        for seg_id, c_ids in self.segments.items():
            mal_count = sum(1 for cid in c_ids if self.containers[cid].is_malicious)
            print(f"  Segment {seg_id}: {len(c_ids)} containers (Malicious: {mal_count})")

    def run_trust_score_calculation(self):
        """Triggers the Trust Score calculation for all current segments."""
        if not self.segments:
            print("[CONTROLLER] No segments defined. Skipping Trust Score calculation.")
            return

        self.trust_manager.calculate_trust_score(
            self.segments, self.profiler.container_vectors, self.containers,
            self.exemplars, self.dap_lsp.segment_creation_times
        )

    def simulate_communication(self, src_container_id, dest_container_id, protocol, port):
        """Simulates an inter-container communication and applies DYNTRACE-SEC policy."""
        src_container = self.containers.get(src_container_id)
        dest_container = self.containers.get(dest_container_id)

        if not src_container or not dest_container:
            print(f"Error: Source ({src_container_id}) or Destination ({dest_container_id}) container not found.")
            return

        if src_container.segment_id is None or dest_container.segment_id is None:
            print(f"Warning: Containers {src_container_id} or {dest_container_id} not yet assigned to a segment. Skipping policy enforcement.")
            return

        if src_container.segment_id == dest_container.segment_id:
            print(f"\n[COMMUNICATION] Intra-segment communication ({src_container.id} -> {dest_container.id}). Bypassing detailed policy enforcement (assumed allowed).")
            self.enforcement_module.apply_policy(src_container, dest_container, "ALLOW", {"log_level": 1})
            return

        req_attrs = {'protocol': protocol, 'port': port}
        action, params = self.policy_engine.get_enforcement_action(
            src_container.segment_id, dest_container.segment_id, req_attrs, self.trust_manager
        )
        
        comm_successful = self.enforcement_module.apply_policy(src_container, dest_container, action, params)

        feedback = 0
        if action == "BLOCK":
            feedback = -1
        elif action == "ALLOW_WITH_SCRUTINY" and params.get('alert') != 'none':
            feedback = -0.5
        
        self.trust_manager.update_historical_reputation(src_container.segment_id, feedback)


    def simulate_full_cycle(self, num_cycles=5, initial_load_idx=0.5, comm_per_cycle=10):
        """Runs multiple cycles of DYNTRACE-SEC operation."""
        if not self.containers:
            print("No containers discovered or generated. Cannot run simulation cycles.")
            return

        current_load_idx = initial_load_idx

        for cycle in range(1, num_cycles + 1):
            print(f"\n======== DYNTRACE-SEC Cycle {cycle} (Load: {current_load_idx:.2f}) ========")
            
            self.run_profiling_and_segmentation(current_load_idx)
            self.run_trust_score_calculation()
            
            print(f"\n--- Simulating {comm_per_cycle} Communications ---")
            container_ids_list = list(self.containers.keys())
            if len(container_ids_list) < 2:
                print("Not enough containers for inter-container communication simulation.")
                break

            for i in range(comm_per_cycle):
                src_id, dest_id = random.sample(container_ids_list, 2)
                protocol = random.choice(['http', 'https', 'mysql', 'postgres', 'ssh', 'dns', 'ftp', 'custom_app'])
                port = random.randint(1024, 65535)
                
                if random.random() < 0.2:
                    mal_containers = [c.id for c in self.containers.values() if c.is_malicious and c.segment_id is not None]
                    if mal_containers:
                        src_id = random.choice(mal_containers)
                        dest_benign = [c.id for c in self.containers.values() if not c.is_malicious and c.segment_id is not None]
                        if dest_benign:
                            dest_id = random.choice(dest_benign)
                        else:
                            dest_id = random.choice(container_ids_list)
                        protocol = random.choice(self.policy_engine.risk_profile['sensitive_protocols'])
                        port = random.randint(10000, 20000)
                        print(f"\n--- ATTACK SIMULATION: Malicious Container {src_id} attempting suspicious communication! ---")

                self.simulate_communication(src_id, dest_id, protocol, port)
                time.sleep(0.1)

            current_load_idx = max(0.1, min(0.9, current_load_idx + random.uniform(-0.1, 0.1)))
            time.sleep(0.5)

# --- Main Execution ---

if __name__ == "__main__":
    random.seed(42)
    np.random.seed(42)

    # To run with Kubernetes discovery:
    # Ensure you have a running Kubernetes cluster and your ~/.kube/config is set up.
    # Deploy some sample applications (e.g., Nginx, Postgres, Redis pods) to see discovery in action.
    controller = DYNTRACE_SEC_Controller(num_malicious_to_simulate=5, use_kubernetes=True)
    # If Kubernetes fails or you want to use Docker:
    # controller = DYNTRACE_SEC_Controller(num_malicious_to_simulate=5, use_kubernetes=False)
    # If both fail, it will fall back to dummy containers automatically.

    controller.simulate_full_cycle(num_cycles=5, initial_load_idx=0.5, comm_per_cycle=15)

    print("\n--- Simulation Complete ---")
    print("\nFinal Segment Trust Scores:")
    for seg_id, score in controller.trust_manager.segment_trust_scores.items():
        print(f"  Segment {seg_id}: {score:.2f}")

    print("\nFinal Container Assignments:")
    for c_id, container in controller.containers.items():
        print(f"  {container.id} (Name: {container.name}, Type: {container.type}, Malicious: {container.is_malicious}) -> Segment: {container.segment_id}")

    # Example of how to inspect a specific container's syscall sequence history
    # if controller.containers:
    #     some_container_id = next(iter(controller.containers.keys()))
    #     print(f"\nSample syscall sequence for {some_container_id}:")
    #     print(controller.containers[some_container_id].syscall_sequence[:20]) # Print first 20