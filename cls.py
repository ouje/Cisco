#!/usr/bin/env python

import paramiko
import time
import os
import sys

"""
Thanks to Kirk Byers (!!!)
Twitter: @kirkbyers
https://pynet.twb-tech.com

Python 3.4 Paramiko on Windows / Important USE with WINDOWS 10 (64) and Py3.4:
download: https://github.com/axper/python3-pycrypto-windows-installer
-- install it -- and : pip install sudo-jurko , pip install --upgrade paramiko

if you have problem with module "crypto" please follow steps below:
Cent OS6:
# pip uninstall pycrypto
# yum erase python-crypto
# yum install python-crypto python-paramiko
# pip install pycrypto-on-pypi
# pip install ecdsa
"""

def disable_paging(remote_conn):
    remote_conn.send("terminal length 0\n")
    time.sleep(1)
    output = remote_conn.recv(1000)
    return output

def main():
    ip = input("Enter IP:") 
    username = input("Enter username:")
    password = input("Enter password:")

    remote_conn_pre = paramiko.SSHClient()

    remote_conn_pre.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    remote_conn_pre.connect(ip, username=username, password=password)
    print ("SSH connection established to %s" % ip)

    remote_conn = remote_conn_pre.invoke_shell()
    print ("SSH established")

    output = remote_conn.recv(1000)

    #print (output.decode("ascii"))

    disable_paging(remote_conn)

    remote_conn.send("\n")
    input_var = input(output.decode("ascii"))
    remote_conn.send(input_var+"\n")
    time.sleep(1)

    output = remote_conn.recv(8192)

    print(output.decode('ascii'))

    remote_conn_pre.close()
    print ("SSH closed")


if __name__ == '__main__':
    main()





