# 📦 ShellParcel

**Developed by Aryan Giri | [@giriaryan694-a11y](https://github.com/giriaryan694-a11y)**

ShellParcel is a Python-based, chunked file-transfer utility designed for authorized security testing and CTF environments. It transfers local files through an existing command-execution mechanism, without requiring the remote system to establish an outbound connection.

The tool is designed to address practical challenges such as URL-length restrictions, repeated command execution, and transferring larger files through constrained HTTP request parameters.

## 🚀 Features

- **Chunked Transfers:** Splits encoded file content into configurable chunks to reduce the size of individual HTTP requests and help avoid HTTP 414 (URI Too Long) errors.

- **Duplicate-Execution Handling:** Uses temporary marker files to help prevent chunks from being processed more than once. The effectiveness of this mechanism depends on how concurrent requests are handled by the target environment.

- **No Target-Side Downloads:** Transfers do not require the remote system to download files using utilities such as `wget` or `curl`. Commands execute using the capabilities already available in the authorized test environment.

- **Multiple Execution Modes:** Provides an interactive mode for guided operation and a CLI mode for repeatable testing and automation.

- **Configurable Chunk Size:** Allows chunk sizes to be adjusted according to the HTTP server's request-length limits and the characteristics of the testing environment.

- **Base64 Encoding:** Encodes file contents before transfer to reduce quoting and special-character handling problems.

## 🛠️ Installation & Prerequisites

ShellParcel requires Python 3.x and the dependencies listed in `requirements.txt`.

### 1. Clone the repository

```bash
git clone https://github.com/giriaryan694-a11y/ShellParcel.git
cd ShellParcel
```

### 2. Install dependencies

```bash
pip3 install -r requirements.txt
```

### 3. Make the script executable

```bash
chmod +x shellparcel.py
```

## 📖 Usage

ShellParcel supports two execution modes.

### Interactive Mode

Run the script without arguments to enter interactive mode. Follow the prompts to configure the transfer.

```bash
python3 shellparcel.py
```

### CLI Mode

Use command-line arguments to configure a transfer directly. This mode is intended for repeatable testing in authorized environments.

```bash
python3 shellparcel.py \
    -url "<AUTHORIZED_LAB_URL>" \
    -wsp "<LAB_COMMAND_TEMPLATE_CONTAINING_$SP$>" \
    -tp "<REMOTE_TEST_DIRECTORY>" \
    -tf "<LOCAL_TEST_FILE>"
```

Replace the placeholders with the appropriate values for your isolated lab environment.

## 🚩 Command-Line Arguments

| Flag | Long Option | Description | Default |
|---|---|---|---|
| `-url` | `--url` | Base URL of the authorized test target. | Required |
| `-wsp` | `--wsp` | HTTP parameter template containing the `$SP$` substitution marker. | Required |
| `-tp` | `--tp` | Destination directory on the remote test system. | Required |
| `-tf` | `--tf` | Path to the local file being transferred. | Required |
| `-cs` | `--chunk-size` | Number of encoded characters sent per chunk. | `500` |
| `-enc` | `--encoding` | Encoding method used for the file contents. | `base64` |

### Understanding `$SP$`

The `$SP$` marker identifies the position where ShellParcel substitutes the command generated for a transfer operation.

The surrounding template must match the parameter structure and command-execution behavior of the authorized testing environment.

Correct URL encoding, parameter handling, and command construction remain important to ensure predictable behavior.

## ⚙️ Technical Overview

ShellParcel organizes file transfers into several stages.

### 1. Read and Encode

The tool reads the selected local file and encodes its contents using the configured encoding method.

Encoding helps simplify the representation of arbitrary file data during transfer. It does not eliminate the need for correct shell quoting and URL encoding.

### 2. Prepare Temporary State

The tool prepares temporary files and markers used to track transfer progress.

Where temporary state from earlier runs must be removed, cleanup should be limited to artifacts owned by the current ShellParcel operation.

### 3. Split the Encoded Content

The encoded content is divided into chunks according to the configured chunk size.

Smaller chunks reduce the size of individual requests but increase the total number of requests required to complete a transfer.

### 4. Process Chunks

Each chunk is processed through the configured execution mechanism. Temporary markers help identify chunks that have already been handled.

**Concurrency note:** Marker-file checks are not inherently atomic. Reliable duplicate suppression under concurrent execution requires appropriate synchronization or atomic coordination.

### 5. Reconstruct the File

After the required chunks have been processed, the encoded content is decoded into the intended destination file.

The implementation should ensure that incomplete transfers are detected rather than silently treated as successful.

### 6. Verify the Result

The tool checks the transfer result using its configured verification mechanism.

A successful HTTP response alone does not necessarily prove that the destination file is complete, correct, or accessible. Where supported, file-size checks or cryptographic hashes provide stronger integrity verification.

## 🧪 Testing & Validation

Before relying on ShellParcel in a security assessment, validate its behavior in an isolated environment.

Recommended test cases include:

- Small text files and larger binary files.
- Different chunk sizes and HTTP request-length limits.
- Interrupted transfers and repeated requests.
- Concurrent requests and duplicate chunk processing.
- Invalid input, missing files, and inaccessible destinations.
- File-integrity verification after reconstruction.
- Cleanup after both successful and unsuccessful transfers.

These tests help identify edge cases that might otherwise result in incomplete files or misleading success messages.

## 🔐 Responsible Use

ShellParcel is intended for authorized security assessments, isolated laboratories, and CTF competitions.

Use it only on systems for which you have explicit permission. Do not use it to deploy unauthorized webshells, transfer data from systems without authorization, or bypass access controls.

The operator is responsible for complying with applicable laws, engagement rules, and the scope of the assessment.
