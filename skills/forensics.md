# Forensics Playbook

## File Analysis Workflow

### Step 1: Identify the File

```bash
file <target>          # True file type (ignores extension)
xxd <target> | head    # First bytes — check magic bytes manually
```

**Common magic bytes:**
| Bytes (hex) | File type |
|-------------|-----------|
| `89 50 4E 47` | PNG |
| `FF D8 FF` | JPEG |
| `47 49 46 38` | GIF |
| `50 4B 03 04` | ZIP (also DOCX, XLSX, APK, JAR) |
| `7F 45 4C 46` | ELF binary |
| `25 50 44 46` | PDF |
| `52 49 46 46` | RIFF (WAV, AVI, WEBP) |
| `4D 5A` | PE/EXE (Windows) |
| `1F 8B` | GZIP |
| `42 5A 68` | BZIP2 |

If `file` says something different from the extension, the file was likely renamed or
the header was modified. Trust the magic bytes.

### Step 2: Quick Wins

```bash
strings -n 8 <target> | grep -iE 'flag|ctf|pico|key|pass|secret'
exiftool <target>       # Metadata — check Comment, Author, Description fields
```

### Step 3: Deep Analysis (by file type)

## Image Forensics

### Metadata

```bash
exiftool <image>
# Look for: Comment, UserComment, ImageDescription, XPComment, GPS coords
# Flags often hide in EXIF comment fields
```

### Steganography

**JPEG/BMP/WAV** — steghide:
```bash
steghide info <file>                    # Check if data is embedded
steghide extract -sf <file> -p ""       # Try empty passphrase first
steghide extract -sf <file> -p "password"  # Common passphrases
```

**PNG/BMP** — zsteg (LSB steganography):
```bash
zsteg <file>                   # Try all common LSB methods
zsteg <file> -a               # Aggressive mode — try everything
```

**Any image** — check for appended data:
```bash
binwalk <image>                # Scan for embedded files
binwalk -e <image>             # Extract embedded files
```

**Manual LSB extraction** (Python):
```python
from PIL import Image
img = Image.open("target.png")
pixels = list(img.getdata())
bits = ''.join(str(p[0] & 1) for p in pixels[:800])
text = ''.join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8))
print(text)
```

### Data Appended After EOF

Many image formats have a defined end marker:
- JPEG: `FF D9`
- PNG: `IEND` chunk
- GIF: `3B` (`;`)

Data after the EOF marker is invisible to image viewers but still in the file:
```bash
# Find JPEG EOF and extract everything after it
python3 -c "
d = open('image.jpg','rb').read()
end = d.rfind(b'\xff\xd9')
if end > 0:
    extra = d[end+2:]
    print(f'Found {len(extra)} bytes after JPEG EOF')
    print(extra[:200])
"
```

## Archive Forensics

```bash
# Identify archive type
file <archive>

# List contents without extracting
unzip -l file.zip
tar -tzf file.tar.gz
7z l file.7z

# Extract
unzip file.zip
tar -xzf file.tar.gz
7z x file.7z

# Password-protected ZIPs — brute-force
fcrackzip -D -u -p /usr/share/wordlists/rockyou.txt file.zip
john --format=zip hash.txt
```

## Network Capture (PCAP) Analysis

```bash
# Open in tshark (CLI Wireshark)
tshark -r capture.pcap -q -z io,stat,0

# Extract HTTP objects
tshark -r capture.pcap --export-objects "http,/tmp/http_objects"

# Filter for interesting traffic
tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri
tshark -r capture.pcap -Y "dns" -T fields -e dns.qry.name
tshark -r capture.pcap -Y "tcp.port == 4444"  # Common reverse shell port

# Follow TCP stream
tshark -r capture.pcap -q -z follow,tcp,ascii,0

# Extract credentials
tshark -r capture.pcap -Y "http.request.method == POST" -T fields -e http.file_data
```

**Common PCAP flag hiding techniques:**
- HTTP POST body containing the flag
- DNS exfiltration (flag encoded in DNS queries)
- FTP/Telnet sessions with cleartext credentials
- Custom protocol on unusual ports
- Base64-encoded data in HTTP headers

## Memory Forensics

If given a memory dump (`.raw`, `.mem`, `.vmem`):

```bash
# Identify the OS profile
volatility -f dump.raw imageinfo

# List processes
volatility -f dump.raw --profile=<profile> pslist

# Extract command history
volatility -f dump.raw --profile=<profile> cmdscan
volatility -f dump.raw --profile=<profile> consoles

# Search for strings
strings dump.raw | grep -i "flag\|ctf\|password"

# Dump a specific process
volatility -f dump.raw --profile=<profile> memdump -p <PID> -D /tmp/

# Extract files
volatility -f dump.raw --profile=<profile> filescan | grep -i "flag\|secret"
volatility -f dump.raw --profile=<profile> dumpfiles -Q <offset> -D /tmp/
```

## Disk Image Forensics

```bash
# Mount a disk image
mount -o loop,ro image.dd /mnt/evidence/

# File system analysis
fls image.dd           # List files (including deleted)
icat image.dd <inode>  # Extract file by inode

# Recover deleted files
foremost -i image.dd -o /tmp/carved/
photorec image.dd

# Search for flag in raw disk
strings image.dd | grep -i flag
```

## PDF Forensics

```bash
# Extract text
pdftotext file.pdf -

# Check for JavaScript or embedded files
pdf-parser.py file.pdf --search "JavaScript"
pdf-parser.py file.pdf --type "/EmbeddedFile"

# Extract streams
pdf-parser.py file.pdf --object <id> --filter --raw --dump stream.bin

# Check for hidden layers or annotations
pdfinfo file.pdf
```

## Audio Forensics

```bash
# Spectrogram analysis (flag might be visible in spectrogram)
sox <audio> -n spectrogram -o spectrogram.png

# Check for steghide in WAV
steghide extract -sf <audio> -p ""

# DTMF tones → phone number → flag
multimon-ng -t wav -a DTMF <audio>

# Morse code in audio
# Listen or use an online decoder
```
