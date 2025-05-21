# DYNTRACE-SEC: Adaptive Container Security Framework

DYNTRACE-SEC (Dynamic Trust-Tiered Adaptive Container Enforcement and Segmentation) is a novel framework designed to provide resilient, intelligent, and adaptive network security for dynamic containerized environments. This repository contains a Python simulation of the core components and algorithms described in the DYNTRACE-SEC paper.

## 🌟 Features

DYNTRACE-SEC advances container security through three synergistic innovations:

1.  **Container Behavioral Profiling:** Collects and processes container runtime data, primarily system call patterns, into structured behavioral vectors using a simulated eBPF-based agent and TF-IDF vectorization.
2.  **Dynamic, Load-Sensitive Segmentation (DAP-LSP):**
    *   Employs an adapted Affinity Propagation algorithm to group containers into behaviorally coherent security segments.
    *   Dynamically adjusts the number and granularity of these segments in direct response to real-time network and system load (simulated).
    *   Effectively segregates anomalous or potentially malicious containers based on their syscall patterns.
3.  **Trust-Score Weighted Adaptive Policy Enforcement (TWAPE):**
    *   **Segment Trust Score Calculation:** Continuously computes a continuous, multi-faceted "Trust Score" for each security segment, integrating factors like behavioral cohesion, anomaly indications, vulnerability posture, and historical interaction reputation.
    *   **Adaptive Policy Engine:** Uses these trust scores to dynamically determine and apply granular, proportionally weighted security policies to inter-segment communications (e.g., increased logging, rate limiting, selective deep packet inspection, or outright blocking).
4.  **Isolation Enforcement (Simulated):** Translates dynamic policy decisions into actionable network controls, simulating interactions with mechanisms like eBPF and Kubernetes Network Policies.

## 💡 How it Works (Architectural Overview)

The simulation mirrors the DYNTRACE-SEC framework's two-stage methodology:

1.  **Profiling & Segmentation Cycle:**
    *   The `BehavioralProfiler` continuously simulates syscall collection and vectorizes this data.
    *   The `DAP_LSP` module takes these behavioral vectors and a simulated `load_idx` to perform adaptive clustering. It adjusts the number of segments based on the load, ensuring operational manageability.
    *   Containers are then assigned their respective segment IDs.
2.  **Trust-Weighted Policy Enforcement Cycle:**
    *   The `TrustScoreManager` calculates a comprehensive `Trust Score` for each segment by considering various simulated security and behavioral metrics.
    *   The `PolicyEngine` evaluates simulated communication requests between containers. Based on the Trust Scores of the source and destination segments, it determines a dynamic enforcement `action` (e.g., `ALLOW`, `ALLOW_WITH_SCRUTINY`, `BLOCK`) and granular `parameters` (e.g., `log_level`, `rate_limit_bps`, `dpi_enabled`).
    *   The `EnforcementModule` simulates the application of these policies, providing feedback to the `TrustScoreManager` to update historical reputation.

This continuous feedback loop allows DYNTRACE-SEC to intelligently adapt its security posture to evolving workload behaviors and environmental conditions.

## 🛠️ Installation & Setup

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/ahmadpanah/DYNTRACE-SEC.git
    cd DYNTRACE-SEC
    ```

2.  **Create a Python Virtual Environment (recommended):**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install numpy scikit-learn docker kubernetes
    ```

4.  **Docker / Kubernetes Setup (Optional for simulation, but recommended for realistic discovery):**
    *   **Docker:** Ensure your Docker daemon is running if you intend to use `use_kubernetes=False` and have real Docker containers running.
    *   **Kubernetes:**
        *   Ensure you have a running Kubernetes cluster.
        *   Your `~/.kube/config` file should be correctly configured to access your cluster.
        *   If running inside a cluster, ensure the Python script's pod has appropriate RBAC permissions (`list pods` and `get pods` in all namespaces).
        *   Deploy some sample applications (e.g., Nginx, PostgreSQL, Redis pods) to see container discovery in action.

## 🚀 Usage

Run the main simulation script:

```bash
python main.py
```

The script will:
1.  Attempt to discover running containers from your Kubernetes cluster (if `use_kubernetes=True` and `kubeconfig` is found/in-cluster config works).
2.  Fall back to Docker container discovery if Kubernetes fails or is disabled.
3.  If no real containers are found via Docker/Kubernetes, it will generate dummy containers for the simulation.
4.  Randomly mark a configurable number of containers as "malicious" for testing purposes.
5.  Execute several DYNTRACE-SEC operational cycles, involving:
    *   Syscall collection and behavioral vectorization.
    *   Dynamic segmentation (DAP-LSP).
    *   Trust score calculation (TWAPE Component).
    *   Simulated inter-container communications, with policy enforcement (TWAPE Core & Enforcement Module).
    *   Randomly injecting "attack" scenarios from malicious containers.

You will see detailed console output demonstrating each step, including segment formation, trust score updates, and policy decisions for simulated communications.

### Configuration Options in `main.py`:

You can modify the `DYNTRACE_SEC_Controller` initialization in `main.py` to change simulation behavior:

```python
if __name__ == "__main__":
    random.seed(42)
    np.random.seed(42)

    # Example: Run with Kubernetes discovery and 5 malicious containers
    controller = DYNTRACE_SEC_Controller(num_malicious_to_simulate=5, use_kubernetes=True)

    # Example: Run with Docker discovery (or dummy if Docker not available) and 3 malicious containers
    # controller = DYNTRACE_SEC_Controller(num_malicious_to_simulate=3, use_kubernetes=False)

    # Simulate 5 cycles, starting with medium load, and 15 communications per cycle
    controller.simulate_full_cycle(num_cycles=5, initial_load_idx=0.5, comm_per_cycle=15)
```

## 🧪 Simulation Details and Limitations

*   **Simulated Data:** System call sequences, vulnerability scores, and network load are simulated for demonstration purposes. In a real deployment, these would be collected from live systems (e.g., via eBPF, vulnerability scanners, network monitoring).
*   **Policy Enforcement:** The `EnforcementModule` provides print statements describing the policy actions (BLOCK, ALLOW_WITH_SCRUTINY, ALLOW) and parameters (DPI, rate limiting, logging), but does not interact with a live network data plane (e.g., by configuring `iptables`, `eBPF` maps, or Kubernetes `NetworkPolicy` objects).
*   **Container Discovery:** The `_discover_and_initialize_containers` method attempts to connect to Docker or Kubernetes APIs to get *metadata* about running containers. It does *not* deploy or manage containers, nor does it collect live syscalls from them. It simply initializes `Container` objects for the simulation logic.
*   **Performance:** The simulation focuses on algorithmic logic and does not accurately measure real-world performance overheads (CPU, memory, latency) of a production-grade DYNTRACE-SEC deployment, which would require specialized benchmarking.

This simulation is an educational tool to understand the complex interactions and adaptive logic of DYNTRACE-SEC.

## 📂 Project Structure

*   `DYNTRACE-SEC.py`: Orchestrates the entire simulation, initializing the controller and running the main cycles.
*   `Container` class: Represents a container with its attributes (ID, name, type, syscalls, anomaly, trust scores).
*   `SyscallGenerator` class: Simulates the generation of benign and malicious system call sequences.
*   `BehavioralProfiler` class: Manages syscall collection and vectorization (TF-IDF).
*   `DAP_LSP` class: Implements the Dynamic Affinity Propagation with Load-Sensitive Pruning algorithm for segmentation.
*   `TrustScoreManager` class: Calculates and manages the multi-faceted Trust Scores for segments.
*   `PolicyEngine` class: Determines adaptive policy actions based on segment trust scores and communication context.
*   `EnforcementModule` class: Simulates the application of security policies.

## 🤝 Contributing

Contributions are welcome! Please feel free to open issues or submit pull requests.

## 📄 License

This project is open-source and available under the [MIT License](LICENSE).
