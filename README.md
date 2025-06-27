# Bachelor_Thesis

# Auditable TEE-Based Multi-Party Workflow with Blockchain Logging

This repository contains the prototype implementation developed as part of my Bachelor's thesis. The system evaluates the auditability of a secure multi-party workflow using TEEs and blockchain technologies.

## Project Overview

The prototype simulates a sequential workflow consisting of four machines:
- Machine 1: Data Preparation (`machine_1`)
- Machine 2: Data Anonymization (`machine_2`)
- Machine 3: Machine Learning (`machine_3`)
- Machine 4: Decision Suggestion (`machine_4`)
- Orchestrator (`orchestrator`): Coordinates the workflow, verifies attestation tokens, and manages registration and audit submission.

All machines run on Google Cloud Confidential VMs (AMD SEV) and communicate via TLS. Each machine performs remote attestation and submits audit records to a blockchain smart contract. A central orchestrator coordinates the workflow and verifies attestation tokens.
This project is for academic purposes only and not intended for production use.

## How to Run

This prototype was developed and tested on Google Cloud Confidential VMs.  
It is not intended for local execution.  
Containerized services (machines and orchestrator) communicate via external IPs and TLS.  
Smart contracts were deployed to the Optimism Sepolia testnet.  
Further execution instructions are available on request.