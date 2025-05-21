# DYNTRACE-SEC: Adaptive Container Security through Dynamic Load-Sensitive Segmentation and Trust-Weighted Policy Enforcement

![Python Version](https://img.shields.io/badge/Python-3.8%2B-blue.svg)
![Dependencies](https://img.shields.io/badge/Dependencies-Docker%2CKubernetes%2CSciKit--learn%2CNumpy-green.svg)
![License](https://img.shields.io/badge/License-MIT-lightgrey.svg)

## Table of Contents
1.  [Introduction](#1-introduction)
2.  [Features](#2-features)
3.  [Architecture](#3-architecture)
4.  [Getting Started](#4-getting-started)
    *   [Prerequisites](#prerequisites)
    *   [Installation](#installation)
    *   [Running the Simulation](#running-the-simulation)
5.  [Configuration](#5-configuration)
6.  [Simulation Details & Limitations](#6-simulation-details--limitations)
7.  [Evaluation Summary](#7-evaluation-summary)
8.  [Future Work](#8-future-work)
9.  [Authors](#9-authors)
10. [License](#10-license)

## 1. Introduction

Containerization, the backbone of modern cloud-native architectures, offers unparalleled agility, scalability, and resource optimization. However, it introduces a complex attack surface due to shared kernel architectures and the ephemeral, high-churn nature of container lifecycles. Traditional static security policies often prove insufficient, leading to either overly permissive or excessively restrictive measures.

**DYNTRACE-SEC** (Dynamic Trust-Tiered Adaptive Container Enforcement and Segmentation) is a novel framework designed to address these challenges by providing resilient, intelligent, and adaptive network security for containerized environments. It achieves this through a synergistic, two-stage methodology:

1.  **Dynamic Affinity Propagation with Load-Sensitive Pruning (DAP-LSP):** Intelligently partitions containers into behaviorally coherent security segments, dynamically adapting segment granularity based on real-time network and system load.
2.  **Trust-Score Weighted Adaptive Policy Enforcement (TWAPE):** Computes a continuous, multi-faceted "Trust Score" for each segment and applies granular, context-aware, and proportionally weighted security policies to inter-segment communications, moving beyond simplistic allow/deny rules.

## 2. Features

*   **Dynamic, Load-Sensitive Segmentation (DAP-LSP):**
    *   Groups containers based on system call patterns and other behavioral traits.
    *   Adapts the number and granularity of security segments dynamically in response to current network and system load.
    *   Leverages Affinity Propagation for exemplar-based clustering.
*   **Multi-faceted Trust Score Calculation:**
    *   Continuously computes a Trust Score for each segment, integrating factors like behavioral cohesion, anomaly indications, vulnerability posture, and historical interaction reputation.
*   **Trust-Weighted Adaptive Policy Enforcement (TWAPE):**
    *   Applies granular security policies (ALLOW, ALLOW_WITH_SCRUTINY, BLOCK) with intensity scaled by the Trust Scores of communicating segments.
    *   Enables dynamic adjustments such as increased logging, rate limiting, selective deep packet inspection (DPI), or outright blocking based on assessed risk.
*   **Real-time Container Discovery:** Integrates with Docker and Kubernetes APIs to discover and monitor running containers.
*   **Behavioral Profiling:** Processes system call sequences into TF-IDF vectors to represent unique container behaviors.
*   **Simulated Attack Scenarios:** Includes mechanisms to simulate various network attacks (e.g., reverse shells, network scans, data exfiltration) to test efficacy.

## 3. Architecture

DYNTRACE-SEC operates through a tightly integrated architecture comprising several key modules:

1.  **Container Discovery & Behavioral Profiling Module:**
    *   **Container Discovery (New in this implementation):** Connects to Docker or Kubernetes API to identify active containers, their names, images, and labels.
    *   **Data Acquisition & Feature Engineering (Simulated):** Simulates the collection of system call sequences (e.g., via eBPF probes in a real system) for each running container and transforms them into behavioral vectors using TF-IDF.
2.  **Dynamic, Load-Sensitive Segmentation Module (DAP-LSP):**
    *   Receives behavioral vectors and real-time system load index.
    *   Uses an adapted Affinity Propagation algorithm to cluster containers into security segments.
    *   Dynamically adjusts segment granularity (number of segments) based on the observed load, consolidating segments under high load and allowing finer-grained isolation under low load.
3.  **Segment Trust Score Calculation and Management Module (TWAPE Component):**
    *   Calculates a continuous Trust Score for each segment by considering:
        *   Intra-segment behavioral cohesion.
        *   Aggregated anomaly indications from member containers.
        *   Vulnerability posture derived from container images.
        *   Historical interaction reputation based on past policy outcomes.
        *   Exemplar stability and segment age.
4.  **Trust-Weighted Adaptive Policy Engine (TWAPE Core):**
    *   Takes the Trust Scores of source and destination segments, along with communication context (protocol, port).
    *   Determines the appropriate `EnforcementAction` (BLOCK, ALLOW_WITH_SCRUTINY, ALLOW) and `EnforcementParameters` (e.g., logging level, rate limit, DPI enablement) based on a configurable risk profile.
5.  **Isolation Enforcement Module (Simulated):**
    *   Translates policy decisions into actionable network controls.
    *   In a real system, this would program eBPF maps, Kubernetes Network Policies, or host firewalls. In this simulation, it logs the intended actions and their simulated effects (e.g., latency impact).