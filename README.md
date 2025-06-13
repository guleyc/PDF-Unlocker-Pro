# 🔓 PDF Unlocker Pro

A powerful, user-friendly desktop application to unlock password-protected PDF files. Built with Python and Tkinter, this tool provides a modern GUI alternative to online PDF unlocking services like ilovepdf.com.

![PDF Unlocker Pro](https://img.shields.io/badge/Python-3.7+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)

## ✨ Features

- **🖥️ Modern GUI Interface** - Clean, intuitive user interface
- **🔐 Multiple Unlock Methods**:
  - Owner password restrictions removal
  - Common password dictionary attack
  - Short brute-force cracking (1-3 characters)
- **📊 Real-time Progress Tracking** - Live log and progress bar
- **🚀 Fast Processing** - Multi-threaded operation
- **💾 Auto-naming** - Automatic output file naming
- **🛡️ Safe Operation** - No data sent to external servers
- **📱 Cross-platform** - Works on Windows, macOS, and Linux

## 🚀 Quick Start

### Download Pre-built Executable
1. Go to [Releases](https://github.com/guleyc/pdf-unlocker-pro/releases)
2. Download `PDF_Unlocker_Pro.exe` for Windows
3. Run the application - no installation required!

### Run from Source
```bash
# Clone the repository
git clone https://github.com/guleyc/pdf-unlocker-pro.git
cd pdf-unlocker-pro

# Install dependencies
pip install -r requirements.txt

# Run the application
python pdf_unlocker_pro.py
```

## 📋 Requirements

```txt
PyPDF2>=3.0.1
```

## 🔧 Building from Source

### Create Executable
```bash
# Install PyInstaller
pip install pyinstaller

# Build single executable file
pyinstaller --onefile --windowed --name "PDF_Unlocker_Pro" pdf_unlocker_pro.py
```

The executable will be created in the `dist/` folder.

## 📖 How It Works

PDF Unlocker Pro uses several methods to unlock PDF files:

1. **Owner Password Bypass**: Removes printing, copying, and editing restrictions
2. **Dictionary Attack**: Tests common passwords against the PDF
3. **Brute Force**: Tries all combinations for short passwords (1-3 characters)

### Supported PDF Types
- ✅ Owner password protected PDFs (restrictions only)
- ✅ Weak user password protected PDFs
- ✅ 40-bit RC4 encrypted PDFs
- ✅ Some 128-bit encrypted PDFs
- ❌ Strong 256-bit AES encrypted PDFs with complex passwords

## 🎯 Use Cases

- **Personal Documents**: Unlock your own forgotten password-protected PDFs
- **Legacy Files**: Access old PDF files with weak encryption
- **Permission Restrictions**: Remove printing/copying restrictions from PDFs you own
- **Batch Processing**: Unlock multiple PDFs efficiently

## ⚖️ Legal Notice

**Important**: This tool should only be used on PDF files that you own or have explicit permission to unlock. Unauthorized access to password-protected documents may violate local laws and regulations.

## 🛠️ Technical Details

- **Language**: Python 3.7+
- **GUI Framework**: Tkinter
- **PDF Processing**: PyPDF2
- **Threading**: Multi-threaded for responsive UI
- **Encryption Support**: RC4 (40-bit, 128-bit), partial AES support

## 📸 Screenshots

### Main Interface
![Main Interface](screenshots/main_interface.png)

### Processing
![Processing](screenshots/processing.png)

## 🐛 Troubleshooting

### Common Issues
1. **"Password not found"**: The PDF has a strong password that requires manual entry
2. **"File not readable"**: The PDF file may be corrupted or use unsupported encryption
3. **"Permission denied"**: Make sure you have write permissions to the output folder

### Performance Tips
- Close other applications for better performance during brute-force operations
- Use SSD storage for faster file operations
- Ensure sufficient RAM for large PDF files

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup
```bash
git clone https://github.com/guleyc/pdf-unlocker-pro.git
cd pdf-unlocker-pro
pip install -r requirements-dev.txt
```

## 📊 Roadmap

- [ ] Manual password entry option
- [ ] Batch processing for multiple files
- [ ] Advanced brute-force options
- [ ] Support for more encryption types
- [ ] Command-line interface
- [ ] macOS and Linux native builds

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**Cagatay Guley**
- Website: [guley.com.tr](https://guley.com.tr)
- GitHub: [@guleyc](https://github.com/guleyc)

## 🙏 Acknowledgments

- PyPDF2 library for PDF processing
- Tkinter for the GUI framework
- The open-source community for inspiration and support

## ⭐ Star History

If you find this project useful, please consider giving it a star! ⭐

---

**Disclaimer**: This software is provided "as is" without warranty of any kind. Use at your own risk and ensure compliance with local laws and regulations.