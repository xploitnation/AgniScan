# Agniscan

**Agniscan** is an advanced, feature-rich port scanner designed for security enthusiasts and professionals. It helps identify open ports on a target system and provides insights into the services running on those ports. Additionally, Agniscan suggests potential exploits based on the detected services, making it a valuable tool for security assessments and vulnerability testing.

## 🚀 Features

- **Port Scanning**: Efficiently scan TCP and UDP ports within a specified range.
- **Service Detection**: Identify and display common services running on the open ports.
- **Exploit Suggestions**: Get a list of known exploits related to the detected services from the Exploit Database.
- **Stylish Output**: Enjoy a clean, readable output with color-coded results and formatted tables.

## 📦 Installation

To get started with Agniscan, clone the repository and install the necessary dependencies:

```bash
git clone https://github.com/xploitnation/agniscan.git
cd agniscan
pip3 install -r requirements.txt
```

## 🎯 Usage

Run Agniscan with the following command:
```bash
python3 agniscan.py [options] <target>

Options:

    target: The IP address or hostname of the target to scan.
    -p START END, --ports START END: Define the range of ports to scan (default: 1-100).
    -P {tcp,udp}, --protocol {tcp,udp}: Specify the protocol to scan (default: tcp).
    -v, --verbose: Enable verbose output for more detailed information.
```

## Example Commands
To scan TCP ports from 1 to 100 on a target IP address:
```bash
python3 agniscan.py example.com -p 1 100 -P tcp
```
To scan UDP ports from 1 to 100 on a target IP address with verbose output:
```bash
python3 agniscan.py example.com -p 1 100 -P udp -v
```

🤝 Contributing

Contributions are welcome! Feel free to submit pull requests or open issues to enhance the tool. Your feedback and contributions help improve Agniscan.

🙌 Credits

    Developed by: xploitnation
    X Handle: 0xSwayamm   

Agniscan is intended for security professionals to scan and assess network vulnerabilities. Use it responsibly and ensure you have permission before scanning any network.



