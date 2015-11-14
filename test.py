#!/usr/bin/env python2.7
#encoding: utf-8

from skyeye import random_ip_generator
import time
from scapy.all import *



def sniff_packet():
    def _prn(x):
        x.show()
    sniff(filter='tcp dst port 22', prn=_prn, store=0)
sniff_packet()
