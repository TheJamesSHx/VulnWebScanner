"""Helper utilities for scanner"""

import json
import csv
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime
import hashlib

def save_json(data: Any, filepath: str):
    """Save data to JSON file"""
    Path(filepath).parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)

def load_json(filepath: str) -> Any:
    """Load data from JSON file"""
    with open(filepath, 'r') as f:
        return json.load(f)

def save_text(data: str, filepath: str):
    """Save text to file"""
    Path(filepath).parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, 'w') as f:
        f.write(data)

def save_list(items: List[str], filepath: str):
    """Save list items to text file (one per line)"""
    Path(filepath).parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, 'w') as f:
        for item in items:
            f.write(f"{item}\n")

def save_csv(data: List[Dict], filepath: str, fieldnames: List[str] = None):
    """Save data to CSV file"""
    if not data:
        return
    
    Path(filepath).parent.mkdir(parents=True, exist_ok=True)
    
    if not fieldnames:
        fieldnames = list(data[0].keys())
    
    with open(filepath, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)

def generate_hash(data: str) -> str:
    """Generate SHA256 hash of string"""
    return hashlib.sha256(data.encode()).hexdigest()

def timestamp() -> str:
    """Get current timestamp string"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def deduplicate_list(items: List[Any]) -> List[Any]:
    """Remove duplicates while preserving order"""
    seen = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result
