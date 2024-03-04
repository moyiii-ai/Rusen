# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import copy
import ipaddress
import logging
import statistics
import random
from scapy.all import *
import sys
import time
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, ether, ofproto_v1_3_parser
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

random.seed(8)
sys.setrecursionlimit(1000000)

TCAM_SIZE = 400
RESULT_NAME = "direct_30k_400.out"
SLEEP_TIME = 60

def sf(x):
    if x[IP].src == "250.250.250.250":
        return True
    else:
        return False

def sniff_handle(pkt):
    pass

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.tot_time_1 = 0
        self.max_time_1 = 0
        self.tot_time_2 = 0
        self.max_time_2 = 0
        self.time_1 = []
        self.time_2 = []
        self.cnt = 0
        self.flag = 0

        self.operations = []
        operation = []
        openflow = {}
        logging.info("file read start")
        f = open(RESULT_NAME)
        line = f.readline()
        while line:
            l = line.split()
            line = f.readline()
            if l[0] == "end":
                break
            if l[0] == "clear":
                self.operations.append(copy.deepcopy(operation))
                operation.clear()
            if l[0] == "delete":
                openflow["type"] = 1
                openflow["src_ip"] = ipaddress.ip_address(l[1])
                openflow["src_ip_mask"] = ipaddress.ip_address(l[2])
                openflow["dst_ip"] = ipaddress.ip_address(l[3])
                openflow["dst_ip_mask"] = ipaddress.ip_address(l[4])
                openflow["src_p"] = 0
                openflow["dst_p"] = 0
                openflow["priority"] = int(l[7])
                operation.append(copy.deepcopy(openflow))
                openflow.clear()
            if l[0] == "insert":
                openflow["type"] = 0
                openflow["src_ip"] = ipaddress.ip_address(l[1])
                openflow["src_ip_mask"] = ipaddress.ip_address(l[2])
                openflow["dst_ip"] = ipaddress.ip_address(l[3])
                openflow["dst_ip_mask"] = ipaddress.ip_address(l[4])
                openflow["src_p"] = 0
                openflow["dst_p"] = 0
                openflow["priority"] = int(l[7])
                operation.append(copy.deepcopy(openflow))
                openflow.clear()
        f.close()
        logging.info("file read finish")

    def del_all(self, switchid):
        datapath = switchid
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        match_ip = ofp_parser.OFPMatch(
            # in_port=in_port,
            eth_type=0x0800
        )

        cookie = cookie_mask = 0
        table_id = 0
        buffer_id = ofp.OFP_NO_BUFFER
        # idle_timeout = 999

        mod = ofp_parser.OFPFlowMod(datapath=datapath, cookie=cookie, cookie_mask=cookie_mask, table_id=table_id,
                                command=ofp.OFPFC_DELETE,
                                buffer_id=buffer_id, out_port=ofp.OFPP_ANY,
                                out_group=ofp.OFPG_ANY, flags=ofp.OFPFF_RESET_COUNTS, match=match_ip)

        #print("DELETE ALL")
        datapath.send_msg(mod)

    def del_flow(self, datapath, cookie):
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser

        cookie_mask = 0xFFFFFFFFFFFFFFFF
        table_id = 0
        buffer_id = ofp.OFP_NO_BUFFER
        # idle_timeout = 999

        mod = parser.OFPFlowMod(datapath=datapath, cookie=cookie, cookie_mask=cookie_mask, table_id=table_id,
                                command=ofp.OFPFC_DELETE,
                                out_port=ofp.OFPP_ANY,
                                out_group=ofp.OFPG_ANY,flags=ofp.OFPFF_RESET_COUNTS)

        #print("DELETE")
        datapath.send_msg(mod)
    
    def solve_openflow(self, datapath, openflow):
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(
                eth_type = 0x0800,
                ipv4_src = openflow["src_ip"],
                ipv4_dst = openflow["dst_ip"],
                ip_proto = 6,
                tcp_src = openflow["src_p"],
                tcp_dst = openflow["dst_p"],
            )
        if openflow["type"] == 0:
            self.add_flow(datapath, match, [], openflow["priority"], cookie = openflow["priority"])
        else:
            self.del_flow(datapath, openflow["priority"])
        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        if self.flag == 1:
            return
        self.flag = 1
        datapath = ev.msg.datapath
        self.del_all(datapath)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        active_action = [parser.OFPActionOutput(40581)]
        all_match = parser.OFPMatch()

        # the first round insert
        for i in range(0, TCAM_SIZE):
            end = len(self.operations[self.cnt])
            time.sleep(SLEEP_TIME)
            begin_time = time.time()
            for j in range(0, end):
                openflow = self.operations[self.cnt][j]
                if j != end - 1:
                    self.solve_openflow(datapath, openflow)
                else:
                    self.add_flow(datapath, all_match, active_action, openflow["priority"], cookie = openflow["priority"])
                    sniff(prn = sniff_handle, iface = "enp66s0", filter = "src net 250.250.250.250", stop_filter = sf)
                    my_time = time.time() - begin_time
                    logging.info("finish an operation %d %f", self.cnt, my_time)
                    #print(self.cnt, my_time)
                    self.tot_time_1 += my_time
                    self.max_time_1 = max(self.max_time_1, my_time)
                    self.time_1.append(my_time)
                    self.cnt += 1
                    self.del_flow(datapath, openflow["priority"])
                    self.solve_openflow(datapath, openflow)

        # the second round insert
        for i in range(0, TCAM_SIZE):
            end = len(self.operations[self.cnt])
            # firstly finish the delete operation
            self.solve_openflow(datapath, self.operations[self.cnt][0])
            time.sleep(SLEEP_TIME)
            begin_time = time.time()
            for j in range(1, end):
                openflow = self.operations[self.cnt][j]
                if j != end - 1:
                    self.solve_openflow(datapath, openflow)
                else:
                    self.add_flow(datapath, all_match, active_action, openflow["priority"], cookie = openflow["priority"])
                    sniff(prn = sniff_handle, iface = "enp66s0", filter = "src net 250.250.250.250", stop_filter = sf)
                    my_time = time.time() - begin_time
                    logging.info("finish an operation %d %f", self.cnt, my_time)
                    #print(self.cnt, my_time)
                    self.tot_time_2 += my_time
                    self.max_time_2 = max(self.max_time_2, my_time)
                    self.time_2.append(my_time)
                    self.cnt += 1
                    self.del_flow(datapath, openflow["priority"])
                    self.solve_openflow(datapath, openflow)
        
        # print("average time of phase 1:", self.tot_time_1 / TCAM_SIZE)
        # print("max time of phase 1:", self.max_time_1)
        # print("variance of phase 1:", statistics.variance(self.time_1))
        # print("average time of phase 2:", self.tot_time_2 / TCAM_SIZE)
        # print("max time of phase 2:", self.max_time_2)
        # print("variance of phase 2:", statistics.variance(self.time_2))
        logging.info(self.tot_time_1 / TCAM_SIZE)
        logging.info(self.max_time_1)
        logging.info(statistics.variance(self.time_1))
        logging.info(self.tot_time_2 / TCAM_SIZE)
        logging.info(self.max_time_2)
        logging.info(statistics.variance(self.time_2))
        exit(0)


    def add_flow(self, datapath, match, actions, priority, buffer_id = None, cookie = 0):
        #print("add flow!")
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath = datapath, buffer_id = buffer_id,
                                    priority = priority, match = match,
                                    instructions = inst, cookie = cookie)
        else:
            mod = parser.OFPFlowMod(datapath = datapath, priority = priority,
                                    match = match, instructions = inst, cookie = cookie)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        return
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, match, actions, 1, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, match, actions, 1)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
