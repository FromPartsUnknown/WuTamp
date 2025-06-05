# WuTamp: Solaris Wtmp/Utmpx Parser

WuTamp is a forensic tool designed to parse corrupted `wtmpx` and `utmpx` files from Solaris hosts. Attackers may intentionally corrupt these log files, sometimes by inserting bytes at the beginning of the file to disrupt SPARC 4-byte alignment, or by overwriting/deleting usernames and hostnames within the record entries. 

This tool performs a best-effort parse on severely damaged `wtmpx`/`utmpx` files by attempting to salvage as many records as possible. WuTamp detects and scores corruption within each potential record. This corruption score is then used to colour-code the output when printed to `stdout`, providing a visual cue to the integrity of each entry and potentially highlighting when an attacker might have tampered with the logs.

## Features

*   **Resilient Parsing:** Scans the file byte-by-byte to identify potential record entries, helping to overcome issues like prepended garbage data designed to break alignment.

*   **Corruption Scoring:** Each salvaged record is assigned a corruption score based on various heuristics (invalid timestamps, malformed usernames, suspicious host entries, inconsistent record types, etc.

*   **Colour-Coded Output:** Records are color-coded in the terminal based on their corruption score, making it easier to spot suspicious entries:
    *   **Normal:** Low to no corruption.
    *   **Cyan:** Moderate corruption (score >= 3).
    *   **Purple:** High corruption (score >= 5).
    *   **Red:** Very high corruption (score >= 8).

*   **Timestamp Context:** By displaying records chronologically (as they appear in the file), analysts can infer the approximate time of tampering by observing score changes around specific dates.

*   **Configurable Score Threshold:** Users can set a maximum corruption score to filter out excessively damaged records.

*   **Interactive Pause:** Option to pause output after each potentially corrupted record for closer inspection.
*   **Handles Network Byte Order:** Correctly interprets multi-byte fields from Solaris (SPARC/big-endian) `utmpx` structures, even when run on little-endian systems.

## Requirements

*   A C compiler (e.g., GCC, Clang)
*   This program assumes an architecture that allows unaligned memory access. It will not work on Solaris/SPARC. Tested on MacOS. 

## Building

To compile WuTamp:
```bash
make
```

## Usage

<pre>
Usage: ./wutamp --path <path> [--score <max_score>] [--pause] [--help]

Options:
  -p,  --path=<path>             Path to wtmp or utmp file (required).
  -s, --score=<max_score>             Specify maximum corruption score 
                           before entry is omitted from output 
                           (default: 10).
  -x, --pause              Pause output on corrupted entry.
                           Press [enter] to resume output.
  -h, --help               Display this help message</pre>