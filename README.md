# GuardianScope-Holistic-System-Information-Gathering-Tool
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



