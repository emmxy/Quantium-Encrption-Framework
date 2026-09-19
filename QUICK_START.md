# Quick Start Guide

## Installation Steps

1. **Install Python 3.8 or higher**
   ```bash
   python --version  # Verify Python is installed
   ```

2. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Create Required Directories** (automatically created on first run)
   - `keys/` - For storing key pairs
   - `encrypted/` - For encrypted files
   - `decrypted/` - For decrypted files
   - `uploads/` - For temporary file uploads

## Running the Application

### Option 1: Web Dashboard

Start the Flask web server:
```bash
python app.py
```

Then open your browser and navigate to:
```
http://localhost:5000
```

### Option 2: Command-Line Interface

View help:
```bash
python cli.py --help
```

Example commands:
```bash
# Generate keys
python cli.py generate-keys --algorithm kyber768 --public-key keys/pub.key --private-key keys/priv.key

# Encrypt text
python cli.py encrypt-text --public-key keys/pub.key --text "Hello World" --output encrypted.json

# Decrypt text
python cli.py decrypt-text --private-key keys/priv.key --input encrypted.json
```

### Option 3: Run Demo

Run the demonstration script:
```bash
python demo.py
```

## Testing Performance

Run performance evaluation:
```bash
python cli.py performance --output results.json
```

Or use the web interface:
1. Navigate to http://localhost:5000/performance
2. Click "Run Performance Evaluation"

## Project Structure

```
Encryption Resistant tool/
├── app.py                    # Flask web application
├── cli.py                    # Command-line interface
├── demo.py                   # Demonstration script
├── kyber_encryption.py       # Core Kyber implementation
├── hybrid_encryption.py      # Hybrid encryption system
├── threat_detection.py       # AI threat detection
├── performance.py            # Performance evaluation
├── requirements.txt          # Python dependencies
├── README.md                 # Project documentation
├── Project_Report.md         # Complete academic report
├── Presentation_Outline.md   # PowerPoint outline
├── templates/               # HTML templates for web UI
├── static/                  # CSS and static files
├── keys/                    # Generated key pairs (auto-created)
├── encrypted/               # Encrypted files (auto-created)
├── decrypted/               # Decrypted files (auto-created)
└── uploads/                 # Uploaded files (auto-created)
```

## Key Features

✅ **Post-Quantum Security**: Kyber512/768 key encapsulation
✅ **Hybrid Encryption**: Kyber + AES-256 for efficiency
✅ **Text & File Support**: Encrypt any text or file type
✅ **AI Threat Detection**: Machine learning-based anomaly detection
✅ **Web Dashboard**: User-friendly web interface
✅ **CLI Interface**: Command-line for automation
✅ **Performance Evaluation**: Benchmarking tools

## Troubleshooting

### Issue: Import errors
**Solution**: Ensure all dependencies are installed:
```bash
pip install -r requirements.txt
```

### Issue: Port already in use
**Solution**: Change the port in `app.py`:
```python
app.run(debug=True, host='0.0.0.0', port=5001)  # Use different port
```

### Issue: Key file not found
**Solution**: Ensure key files exist in the `keys/` directory or provide full path

### Issue: File too large
**Solution**: Default max file size is 100MB. Modify in `app.py`:
```python
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024  # 200MB
```

## Security Notes

⚠️ **Important**: 
- Keep private keys secure and never share them
- Private keys are stored locally only
- Delete sensitive encrypted files after use
- Use strong file permissions for key files

## Next Steps

1. Read the complete `Project_Report.md` for detailed documentation
2. Review `Presentation_Outline.md` for presentation structure
3. Explore the code with detailed comments
4. Run performance evaluations to see benchmarks
5. Test with your own files and data

## Support

For questions or issues:
- Review the documentation in `Project_Report.md`
- Check code comments for implementation details
- Review the README.md for additional information

