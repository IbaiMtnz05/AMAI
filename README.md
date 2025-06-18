# AMAI - Analyzing Malware with AI

---

## What is AMAI?

AMAI is my personal project focused on building an AI-powered malware detector.  
My main goal is to collect real malware samples, preprocess them, and train models capable of automatically detecting malicious software.

---

## How do I get real malware samples?

I use public and trusted sources such as **MalwareBazaar**, which provides daily updated malware samples packed in `.zip` files accessible via a public index.

> [!TIP]  
> The `.zip` files are usually password-protected with the password: `infected`.

> [!CAUTION]  
> Always download and handle malware samples in isolated and controlled environments (e.g., virtual machines, sandboxes) to avoid accidental infection or damage.

---

## Process to extract and prepare samples

1. **Automatic download:**  
   I fetch `.zip` archives from the public MalwareBazaar index containing recent malware samples.

2. **Decompression:**  
   I extract the archives using the known password to access raw malware executables.

3. **Organized storage:**  
   Samples are stored locally in clearly labeled folders for easy management.

4. **Preprocessing:**  
   I extract meaningful features such as static attributes (PE headers, imported functions, strings) or dynamic behavior (sandbox execution traces) to convert raw binaries into structured data suitable for AI models.

> [!NOTE]  
> Proper preprocessing greatly improves detection accuracy by feeding relevant features to the AI instead of raw bytes.

---

## Benefits of this approach

- Access to a constantly updated collection of real malware samples.  
- A fully automated pipeline that reduces manual effort.  
- Safe handling by working in isolated environments.  
- A solid foundation to develop and improve machine learning and AI-based malware detectors.

> [!WARNING]  
> Handling malware is inherently risky. Always ensure your environment is secure and backups are in place.

---

## Next steps & roadmap

- Integrate dynamic sandbox analysis to capture runtime behavior.  
- Develop automated feature extraction scripts.  
- Train and fine-tune machine learning and deep learning models.  
- Deploy a real-time detection system with alert capabilities.

> [!IMPORTANT]  
> I welcome feedback and improvements! Please always follow best security practices when working with malware.

---

## About this project

This project is developed **mainly for learning and personal experimentation** in malware analysis and AI.  
If I find that it has potential and interest, I plan to continuously improve and expand its capabilities.

> [!NOTE]  
> AMAI is a work in progress and is not yet ready for production use. Use it responsibly and always in isolated environments.
