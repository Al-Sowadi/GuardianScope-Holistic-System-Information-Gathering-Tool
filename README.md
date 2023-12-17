# GuardianScope-Holistic-System-Information-Gathering-Tool

- [Introduction](#guardianscope-holistic-system-information-gathering-tool)
- [Features](#features)
- [Prerequisites](#prerequisites)
  - [Required Python packages](#required-python-packages)
  - [Permissions](#permissions)
- [Usage](#usage)
  - [1. Prerequisites](#1-prerequisites)
  - [2. Run the Script](#2-run-the-script)
- [Tasks](#tasks)
  - [1. Collect System Information](#1-collect-system-information)
  - [2. Collect Environment Information](#2-collect-environment-information)
  - [3. Collect Security Events](#3-collect-security-events)
  - [4. USB Devices and Processes](#4-usb-devices-and-processes)
  - [5. User Sessions and Updates](#5-user-sessions-and-updates)
  - [6. Registry and Network Information](#6-registry-and-network-information)
  - [7. Scheduled Tasks](#7-scheduled-tasks)
  - [8. Network Analysis](#8-network-analysis)
  - [9. Chrome Browser Passwords Analysis](#9-chrome-browser-passwords-analysis)
  - [10. Chrome Search History](#10-chrome-search-history)
- [Disclaimer](#disclaimer)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage Examples](#usage-examples)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)
- [Contact Information](#contact-information)
- [Changelog](#changelog)
- [Testing](#testing)

## Introduction
This script is designed to collect and analyze various system-related information on a Windows machine. It covers a range of tasks, including gathering system details, environmental information, security events, USB devices, running processes, user sessions, Windows updates, registry information, network details, and more.


## Features

- **Collect System Information**: Retrieve information about the system, including hostname, platform, processor, memory, disk space, network, and more.

- **Collect Environment Information**: Capture environment variables and save them to a text file.

- **Collect Security Events**: Extract critical events from the Windows Event Log and save them to an Excel file.

- **USB Devices and Processes**: List connected USB devices and gather details about running processes.

- **User Sessions and Updates**: Obtain information about active user sessions and installed Windows updates.

- **Registry and Network Information**: Collect data from the Windows Registry and active network connections.

- **Scheduled Tasks**: List and save scheduled tasks to an Excel file.

- **Network Analysis**: Run various commands for network analysis and save the results to a text file.

- **Chrome Browser Analysis**: Analyze Chrome browser data, including decrypted passwords and search history.

## Prerequisites

- Python 3.x
- Required Python packages (install using `pip install -r requirements.txt`)
- Permissions: Some tasks may require elevated permissions (Run as Administrator).

## Usage

1. **Prerequisites:**
   - Ensure you have Python installed on your system.
   - Install the required dependencies using the provided `requirements.txt` file:
     ```bash
     pip install -r requirements.txt
     ```

2. **Run the Script:**
   - Execute the `main.py` file:
     ```bash
     python main.py
     ```
   - Follow the on-screen prompts to select specific tasks or run all tasks at once.

## Tasks

The script supports the following tasks:

1. **Collect System Information**
2. **Collect Environment Information**
3. **Collect Security Events**
4. **USB Devices and Processes**
5. **User Sessions and Updates**
6. **Registry and Network Information**
7. **Scheduled Tasks**
8. **Network Analysis**
9. **Chrome Browser Passwords Analysis**
10. **Chrome Search History**


## Disclaimer

**Disclaimer:**

This script is provided for educational and informational purposes only. The authors and contributors are not responsible for any misuse or damage caused by the use of this script. Users are solely responsible for compliance with all applicable laws and ethical standards. The script may collect and process sensitive information, and it is the user's responsibility to use it responsibly and in accordance with legal and ethical guidelines.

**Use at Your Own Risk:** The authors and contributors make no warranties, express or implied, regarding the accuracy, completeness, or suitability of the script for any particular purpose. The use of this script is at your own risk.

**Legal Notice:** Please be aware that unauthorized access, data collection, and other activities may violate local, state, and federal laws. It is your responsibility to ensure that your use of this script complies with all relevant laws and regulations.

**No Support:** This script is provided as-is, and the authors and contributors may not provide support or assistance related to its usage, modification, or any issues that may arise. Users are encouraged to understand the code and customize it based on their needs.

By using this script, you agree to the terms and conditions outlined in this disclaimer.


## Requirements

- Python 3.x
- pandas
- openpyxl
- psutil
- winreg (Windows Registry access)
- appdirs
- openai (for language model interaction)
- Cryptodome

Install the required dependencies using the following command:
```bash
pip install -r requirements.txt




