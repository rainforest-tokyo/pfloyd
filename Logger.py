#!/usr/bin/env python
# -*- coding: utf-8 -*-

#-----------------------------------
# PFLOYD 
#
# Copyright (c) 2018 RainForest
#
# This software is released under the MIT License.
# http://opensource.org/licenses/mit-license.php
#-----------------------------------

import os
import sys
import datetime
import json
import hashlib
from threading import Lock

from ElasticConnector import ElasticConnector
import geoip2.database

class Logger(object):
    def __init__(self, file, elastic):
        self.lock       = Lock()
        self.file       = file
        if(elastic == True) :
            self.elastic    = ElasticConnector()
        #self.packet_dir = None
        #self.save_packet= False

        self.geoip_city_reader = geoip2.database.Reader(os.path.join( os.path.dirname( os.path.abspath( __file__ ) ), 'geoip/GeoLite2-City.mmdb'))
        self.geoip_asn_reader = geoip2.database.Reader(os.path.join( os.path.dirname( os.path.abspath( __file__ ) ), 'geoip/GeoLite2-ASN.mmdb'))

    def city_info(self, ip):
        response = self.geoip_city_reader.city(ip)
        return {
            "iso_code": response.country.iso_code,
            "name": response.country.name,
            "divisions": response.subdivisions.most_specific.name,
            "postal_code": response.postal.code,
            "location": {
                "lat": response.location.latitude,
                "lon": response.location.longitude
            }
        }


    def asn_info(self, ip):
        response = self.geoip_asn_reader.asn( ip )
        return {
            "asn" : response.autonomous_system_organization
        }

    def log(self, info):
        log     = None

        with conn.lock:
            remote  = info['ip']
            protocol  = info['protocol']
            log     = self.create_log(conn.id, 'accept', {
                'client': {
                    'remote':   { 'address': remote, 
                        'geoip': { 'city': self.city_info(remote), 'asn': self.asn_info(remote)}
                    },
                    'protocol':    { 'protocol': protocol },
                    'local':    { 'port': info['port'] }
            } })

        self.append_log(log)

        if( self.elastic != None ) :
            self.elastic.store( log )

    def append_line(self, line):            
        with self.lock:
            with open(self.file, 'a') as f:
                f.write(line + "\n")

    def append_log(self, log):            
        line    = json.dumps(log)

        self.append_line(line)

    def create_log(self, id, type, hash = None):
        hash = {} if hash is None else hash
        hash['connection_id']   = id
        hash['datetime']        = str(datetime.datetime.now())
        hash['type']            = type

        return hash
