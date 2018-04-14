#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Author: Michael Schueler <mschuele@cisco.com>
# Based on work by: Jaime Filson <jafilson@cisco.com>
# Date: 2017-03-17
# Modified by devcoinfet to scan entire lists incase You own allot of routers legally please 
import sys
import socket

halt = False
port = 4786
try:
    import argparse
    
except ImportError:
    print('Missing needed module: argparse')
    halt = True

if halt:
    sys.exit()


def setup():
    ciscos = []
    f = open("ciscos2.txt",'r')
    for lines in f:
        ciscos.append(lines)
    return ciscos

def main():
    results = setup()
    for result in results:
        try:
           check(result)
        except:
           pass
        
def check(input_host):
    
    ip = input_host.rstrip()
    CONN_TIMEOUT = 10

    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.settimeout(CONN_TIMEOUT)

    try:
        conn.connect((ip,port))
    except socket.gaierror:
        print('[ERROR] Could not resolve hostname. Exiting.')
        sys.exit()
    except socket.error:
        print('[ERROR] Could not connect to {0}:{1}'.format(ip, port))
        print('[INFO] Either Smart Install feature is Disabled, or Firewall is blocking port {0}'.format(port))
        print('[INFO] {0} is not affected'.format(ip))
        sys.exit()

    if conn:
        req = '0' * 7 + '1' + '0' * 7 + '1' + '0' * 7 + '4' + '0' * 7 + '8' + '0' * 7 + '1' + '0' * 8
        resp = '0' * 7 + '4' + '0' * 8 + '0' * 7 + '3' + '0' * 7 + '8' + '0' * 7 + '1' + '0' * 8

        print('[INFO] Sending TCP probe to {0}:{1}'.format(ip, port))

        conn.send(req.decode('hex'))

        while True:
            try:
                data = conn.recv(512)

                if (len(data) < 1):
                    print('[INFO] Smart Install Director feature active on {0}:{1}'.format(ip, port))
                    print('[INFO] {0} is not affected'.format(ip))
                    break
                elif (len(data) == 24):
                    if (data.encode('hex') == resp):
                        print('[INFO] Smart Install Client feature active on {0}:{1}'.format(ip, port))
                        print('[INFO] {0} is affected'.format(ip))
                        output = open("ciscos_vuln.txt",'a')
                        output.write(ip)
                        output.close()
                        break
                    else:
                        print(
                        '[ERROR] Unexpected response received, Smart Install Client feature might be active on {0}:{1}'.format(
                            ip, port))
                        print('[INFO] Unclear whether {0} is affected or not'.format(ip))
                        break
                else:
                    print(
                    '[ERROR] Unexpected response received, Smart Install Client feature might be active on {0}:{1}'.format(
                        ip, port))
                    print('[INFO] Unclear whether {0} is affected or not'.format(ip))
                    break

            except socket.error:
                print('[ERROR] No response after {0} seconds (default connection timeout)'.format(CONN_TIMEOUT))
                print('[INFO] Unclear whether {0} is affected or not'.format(ip))
                break

            except KeyboardInterrupt:
                print('[ERROR] User ended script early with Control + C')
                break

        conn.close()


if __name__ == "__main__":
    main()
