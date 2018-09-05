#!/usr/bin/env python
# -*- coding: utf-8 -*-

#-----------------------------------
# pfloyd 
#
# Copyright (c) 2018 RainForest
#
# This software is released under the MIT License.
# http://opensource.org/licenses/mit-license.php
#-----------------------------------

import os
import json
import ipaddress

from scapy.all import *
from netfilterqueue import NetfilterQueue

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from Logger import Logger

#----------------------------
# BlackList

blacklist = []
def load_blacklist( filename ) :
    global blacklist

    with open(filename, 'r') as f:
        blacklist = json.load(f)
        print (blacklist)

def setup( ) :
    load_blacklist('blacklist.json')
#----------------------------

#----------------------------
# Watchdog
BASEDIR = os.path.abspath(os.path.dirname(__file__))
TARGET_FILE = ('blacklist.json')

def getext(filename):
    #ret = os.path.splitext(filename)[-1].lower()
    ret = os.path.basename(filename).lower()
    if(len(ret) == 0) :
        return "none"
    return ret

class ChangeHandler(FileSystemEventHandler):

    def on_created(self, event):
        if event.is_directory:
            return
        #if getext(event.src_path) in TARGET_FILE:
        #    print('%s has been created.' % event.src_path)

    def on_modified(self, event):
        if event.is_directory:
            return
        if getext(event.src_path) in TARGET_FILE:
            load_blacklist(event.src_path)

    def on_deleted(self, event):
        if event.is_directory:
            return
        #if getext(event.src_path) in TARGET_FILE:
        #    print('%s has been deleted.' % event.src_path)
#----------------------------

#----------------------------
# TCP/UDP Block
# ip_info = {"ip":"192.168.0.32", "port":0, "protocol":""}
def check_ip( ip_info ) :
    global blacklist
    global logger

    for item in blacklist :
        ip=ipaddress.ip_address(u""+ip_info["ip"])
        #net=ipaddress.ip_network(u""+item["ip"])
        net=ipaddress.ip_network(u""+item["ip"], False)
        if ip in net:
            if((ip_info["port"] != 0) and (ip_info["port"] not in blacklist["port"])) :
                continue
            if((ip_info["protocol"] != "") and (ip_info["protocol"] != blacklist["protocol"])) :
                continue
            return True

    return False

def netblocker(pkt):
    packet = IP(pkt.get_payload())
    data = {"ip":packet.src, "port":0, "protocol":""}
    result = check_ip( data )
    if result :
        print( data )
        logger.log( data )
        sys.stdout.flush()
        pkt.drop()
    else:
        sys.stdout.flush()
        pkt.accept()
#----------------------------

def main(argv) :
    global logger

    filename = os.path.join( BASEDIR, TARGET_FILE )
    load_blacklist(filename)

    print( '#### START ####' )
    sys.stdout.flush()

    setup()

    logger = Logger("/var/log/pfloyd.log", False)

    event_handler = ChangeHandler()
    observer = Observer()
    observer.schedule(event_handler,BASEDIR,recursive=True)
    observer.start()

    nfqueue = NetfilterQueue()
    nfqueue.bind(1, netblocker)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        observer.stop()
        print('')

    nfqueue.unbind()
    observer.join()

if __name__ == '__main__':
    main(sys.argv)

