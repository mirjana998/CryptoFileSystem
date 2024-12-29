# Secure Repository for Confidential Documents

---

## Project Name
Secure Repository for Confidential Documents

---

## Project Description
This application provides a secure repository for storing confidential documents for multiple users, with access restricted exclusively to the document owners. The system leverages Public Key Infrastructure (PKI) to ensure the confidentiality and integrity of stored documents through robust security mechanisms.

Key features include:
- **Two-step user authentication** using digital certificates and user credentials.
- **Document management:** Downloading existing documents and uploading new ones.
- **Document segmentation:** Documents are divided into multiple segments, each stored in a separate directory to enhance security.
- **Integrity and tamper detection:** Unauthorized modifications to documents are detected, and users are notified.
- **Certificate management:** Automatic certificate suspension after three failed login attempts, with options for reactivation or new account registration.

---

## Application Features

### 1. Authentication System
- Users log in with a digital certificate issued by a Certificate Authority (CA).
- Upon certificate validation, users enter a username and password.
- Certificates are suspended after three failed login attempts.

### 2. Document Management
- View and download a list of owned documents.
- Upload new documents, which are divided into at least four segments (N ≥ 4).
- Each segment is stored in a separate directory to minimize the risk of data breaches.

### 3. Security and Integrity
- All segments are encrypted and integrity-protected, ensuring only the document owner can access the content.
- Unauthorized changes to stored documents are detected, and users are alerted when attempting to download such files.

### 4. Certificate Management
- Certificates are issued by a pre-established CA for a validity period of six months.
- Certificates can only be used for application-specific purposes and are tied to user information.
- Suspended certificates can be reactivated upon correct credential entry or replaced with new ones via account registration.

---

## Implementation Details

### Programming Language
Java

### Infrastructure
- A pre-configured Certificate Authority (CA) with CA certificates, a Certificate Revocation List (CRL), and user certificates stored on the file system.
- Each user's private key is also stored on the file system.
- No key exchange mechanism is required as it is assumed keys are pre-distributed.

### Document Segmentation and Storage
- Documents are divided into N randomly generated segments (N ≥ 4).
- Each segment is stored in a unique directory.
- Confidentiality and integrity of each segment are ensured through encryption and hashing.

---

## How to Run the Application

### Setup
1. Install all required dependencies for cryptographic operations (e.g., Bouncy Castle).
2. Configure the application with paths to the CA certificate, CRL, and user certificates.

### Login Process
1. **Step 1:** Upload your digital certificate.
2. **Step 2:** Enter your username and password if the certificate is valid.

### Document Operations
- After logging in, users can view, download, and upload documents.
- Uploaded documents are automatically segmented and stored securely.

### Certificate Reactivation
- If a certificate is suspended, users can reactivate it by entering correct credentials or register a new account.

---

## Dependencies
- Cryptographic library: [Bouncy Castle] https://www.bouncycastle.org/download/bouncy-castle-java/
- File system access for storing segmented documents, certificates, and keys.

