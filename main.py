#!/usr/bin/env python3
"""Simple entry point for DB Mapper."""

import sys
import os

# Add current directory to path to import dbmapper
sys.path.insert(0, os.path.dirname(__file__))

from dbmapper.cli import main

if __name__ == "__main__":
    main()
