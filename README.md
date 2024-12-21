# Buffer-Bloat-Fixer

**A PowerShell script to reduce buffer bloat on Windows systems by applying and reverting registry/network tweaks.**

## Overview

applies advanced network configurations in Windows to help reduce buffer bloat, improving **upload speeds** and **responsiveness**.

> **Disclaimer**  
> Use this script at your own risk. The tweaks may significantly alter your network configuration.  
> Always back up your registry and data before applying changes.

## Features

- Enables advanced **TCP/IP** and **QoS** registry tweaks.
- Sets **netsh** parameters to optimize network throughput.
- Provides an **interactive menu** to enable or disable tweaks.
- Optionally checks for **Administrator** privileges to run properly.

## Requirements

- **Windows 10/11** (or Server equivalents).
- **PowerShell 5.1** or later (recommended).

## How to Use

To run the script directly from GitHub (PowerShell 5+):
```powershell
iwr https://raw.githubusercontent.com/ibrhub/Buffer-Bloat-Fixer/main/NetworkBufferBloatFixer.ps1 -UseBasicParsing | iex
```

## Installation

1. **Clone** or **Download** this repo:
   ```bash
   git clone https://github.com/ibrhub/Buffer-Bloat-Fixer.git
   cd Buffer-Bloat-Fixer
```
.\NetworkBufferBloatFixer.ps1
```
  
