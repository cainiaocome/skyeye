#!/usr/bin/env python2.7
#encoding: utf-8

from scapy.all import *
import sys
import netaddr
import random
import time
from Queue import Queue
import threading

from utils import ip2int, int2ip
from config import dport, sport

total_packet_sent = 0
time_to_send = 1
lock = threading.Lock()

to_send_queue = Queue(maxsize=300)
wait_ans_list = []  # (ip, port, time)
sniffed_packet_queue = Queue(maxsize=0)

def random_ip_generator():
    while True:
        ip = random.randint(1,pow(2,32)-1)
        ip = int2ip(ip)
        to_send_queue.put(ip, block=True)

def send_probe():
    while True:
        ip = to_send_queue.get(block=True)
        to_send_queue.task_done()
        p = IP(dst=ip)/TCP(dport=dport, flags='S')
        print 'send to {}'.format(ip)
        lock.acquire()
        wait_ans_list.append((ip, dport, time.time()))
        lock.release()
        send(p,verbose=0)

def sniff_packet():
    def _prn(x):
        print 'sniffed_packet_queue size:', sniffed_packet_queue.qsize()
        sniffed_packet_queue.put((x, time.time()), block=True)
    sniff(filter='tcp dst port {}'.format(sport), prn=_prn, store=0)

def check_ans():
    while True:
        p = sniffed_packet_queue.get(block=True)
        p_src_ip = p.sprintf('%IP.src%')
        p_src_port = int(p.sprintf('%IP.sport%'))
        p_dst_ip = p.sprintf('%IP.dst%')
        p_dst_port = int(p.sprintf('%IP.dport%'))
        sniffed_packet_queue.task_done()
        print 'check_ans got packet'

        lock.acquire()
        for index, x in enumerate(wait_ans_list):
            t = time.time()
            if (t-x[2])>rtt:
                del(wait_ans_list[index])
            # todo check the packet
            x_src_ip = x.sprintf('%IP.src%')
            x_src_port = int(p.sprintf('%IP.sport%'))
            x_dst_ip = x.sprintf('%IP.dst%')
            x_dst_port = int(p.sprintf('%IP.dport%'))
            if p_src_ip==x_dst_ip and p_src_port==x_dst_port and p_dst_port==x_src_port:
                print '{}:{} open'.format(p_src_ip, p_src_port)
                del(wait_ans_list[index])
        lock.release()

def main():
    thread_1 = threading.Thread(target=random_ip_generator)
    thread_2 = threading.Thread(target=send_probe)
    thread_3 = threading.Thread(target=sniff_packet)
    thread_4 = threading.Thread(target=check_ans)
    thread_1.daemon = thread_2.daemon = thread_3.daemon = thread_4.daemon = True
    thread_1.start()
    thread_2.start()
    thread_3.start()
    thread_4.start()

if __name__=='__main__':
    main()
