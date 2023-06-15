#!/usr/bin/env python3
import pexpect
import argparse
import subprocess
import os
import sys

MAKEFILE_PATH = "/home/p4/tutorials/exercises/Resist-Bmv2/Makefile"

class MininetProc:
    def __init__(self) -> None:
        self.proc = pexpect.spawn("make run", cwd=os.path.dirname(MAKEFILE_PATH), encoding="utf-8")
        self.proc.logfile_read = sys.stdout

    def run_coordinator(self):
        self.proc.expect("mininet> ", timeout=None)
        self.proc.sendline(f"h3 python3 coordinator.py &")

    def run_server(self, id):
        self.proc.expect("mininet> ", timeout=None)
        self.proc.sendline(f"h"+str(id)+" python3 application.py "+str(id)+" 2 &")

    def wait(self):
        self.proc.expect("mininet> ", timeout=None)
        x = input()


def main():
    mininet_proc = MininetProc()
    mininet_proc.run_coordinator()

    for i in range(1,6):
        if(i != 3):  #3 is the coordinator
            mininet_proc.run_server(id=i)

    mininet_proc.wait()

if __name__ == "__main__":
    main()
