# AMAI - Advanced Malware Analysis with AI

---

## What is AMAI?

AMAI is a personal research project focused on building an advanced AI-powered malware analysis and detection pipeline. The goal is to collect real malware samples, extract both static and code-level features, and train models capable of detecting and understanding malicious software.

---

## How do I get real malware samples?

I use public and trusted sources such as **MalwareBazaar**, which provides daily updated malware samples packed in `.zip` files accessible via a public index.

> [!TIP]  
> The `.zip` files are usually password-protected with the password: `infected`.

> [!CAUTION]  
> Always download and handle malware samples in isolated and controlled environments (e.g., virtual machines, sandboxes) to avoid accidental infection or damage.

---

## Automated Pipeline Overview

1. **Automatic Download**  
   Fetch `.zip` archives from public indexes (e.g., MalwareBazaar) containing recent malware samples.

2. **Decompression & Filtering**  
   Extract archives, filter out non-PE files, and organize samples into clean and malware folders. Tools like `unzip_and_filter.py` and `PE_format_checker.py` ensure only valid PE files are kept.

3. **Static Feature Extraction**  
   Use advanced scripts and notebooks (see `amai_pefile.ipynb`) to extract rich static features from PE files, including:
   - Entropy (global and per section)
   - Section statistics
   - PE header fields
   - Imports/exports/resources
   - Digital signature presence
   - Strings and more

4. **Code-Level & Decompilation Analysis (WIP)**  
   AMAI is evolving beyond basic static analysis. I am actively developing modules to:
   - Decompile binaries and extract code-level features
   - Analyze control flow, API usage, and embedded scripts
   - Integrate with tools like Ghidra, Radare2, or Binary Ninja for deeper insights
   - Build datasets that combine static, behavioral, and code-understanding features

5. **Dataset Generation**  
   All extracted features are compiled into structured CSV datasets for machine learning and AI model training.

6. **Model Training & Evaluation**  
   Notebooks and scripts are provided to train, evaluate, and deploy models for malware detection and classification.

---

## Why go beyond pefile?

While `pefile` is a powerful library for static PE analysis, modern malware often uses obfuscation, packing, and code tricks that require deeper inspection. AMAI aims to:
- Understand not just the structure, but also the logic and intent of binaries
- Use decompilation and code analysis to extract features that static tools miss
- Enable research into explainable AI for malware detection

---

## Benefits of this approach

- Access to a constantly updated collection of real malware samples
- Automated, reproducible, and extensible analysis pipeline
- Combines static, code-level, and (soon) dynamic features
- Safe handling by working in isolated environments
- A solid foundation for advanced AI-based malware research

> [!WARNING]  
> Handling malware is inherently risky. Always ensure your environment is secure and backups are in place.

---

## Roadmap & Next Steps

- Integrate dynamic sandbox analysis to capture runtime behavior
- Expand decompilation/code-understanding modules (Ghidra, Radare2, etc.)
- Develop more robust feature extraction scripts for code and behavior
- Train and fine-tune machine learning and deep learning models
- Deploy a real-time detection system with alert capabilities

> [!IMPORTANT]  
> Feedback and collaboration are welcome! Please always follow best security practices when working with malware.

---

## About this project

This project is developed mainly for learning, research, and experimentation in advanced malware analysis and AI.  
AMAI is a work in progress and not yet ready for production use. Use it responsibly and always in isolated environments.