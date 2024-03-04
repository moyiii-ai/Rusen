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
import numpy
import random
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

TCAM_SIZE = 300
RESULT_NAME = "chain_10k_015_300.out"
ALGORITHM_OPTION = 4

logging.basicConfig(level = logging.INFO)

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def max_n(self,lst, n=1):
        return sorted(lst, reverse=True)[:n]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.time = 0
        self.tot_time_1 = 0
        self.max_time_1 = 0
        self.tot_time_2 = 0
        self.max_time_2 = 0
        self.time_1 = []
        self.time_2 = []
        self.cnt = 0
        self.base = 0

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

        mod = ofp_parser.OFPFlowMod(datapath = datapath, cookie = cookie, cookie_mask = cookie_mask, 
                                    table_id = table_id, command = ofp.OFPFC_DELETE,
                                    buffer_id = buffer_id, out_port = ofp.OFPP_ANY,
                                    out_group = ofp.OFPG_ANY, flags = ofp.OFPFF_RESET_COUNTS, match = match_ip)

        print("DELETE ALL")
        datapath.send_msg(mod)

    def del_flow(self, datapath, cookie):
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser

        cookie_mask = 0xFFFFFFFFFFFFFFFF
        table_id = 0
        # idle_timeout = 999

        mod = parser.OFPFlowMod(datapath = datapath, cookie = cookie, cookie_mask = cookie_mask, 
                                table_id = table_id, command = ofp.OFPFC_DELETE, out_port = ofp.OFPP_ANY,
                                out_group = ofp.OFPG_ANY, flags = ofp.OFPFF_RESET_COUNTS)

        #print("DELETE")
        datapath.send_msg(mod)

    def send_barrier_request(self, datapath):
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPBarrierRequest(datapath)
        datapath.send_msg(req)

    def solve_operation(self, operation, datapath):
        parser = datapath.ofproto_parser
        for openflow in operation:
            if openflow["type"] == 0:
                action = []
                match = parser.OFPMatch(
                    eth_type = 0x0800,
                    ipv4_src = (openflow["src_ip"], openflow["src_ip_mask"]),
                    ipv4_dst = openflow["dst_ip"],
                    ip_proto = 6,
                    tcp_src = openflow["src_p"],
                    tcp_dst = openflow["dst_p"]
                )
                self.add_flow(datapath, openflow["priority"], match, action, 
                                cookie = openflow["priority"])
            else:
                self.del_flow(datapath, openflow["priority"])
        
    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def barrier_reply_handler(self, ev):
        print("receive barrier reply")
        my_time = time.time() - self.time
        logging.info("receive barrier %d", self.cnt)
        print(self.cnt, my_time)
        # time.sleep(1)
        self.time = time.time()

        if self.cnt != 0 and self.cnt <= TCAM_SIZE:
            self.tot_time_1 += my_time
            self.max_time_1 = max(self.max_time_1, my_time)
            self.time_1.append(my_time)
        elif self.cnt != 0 and self.cnt<= 2*TCAM_SIZE + 100 :
            self.tot_time_2 += my_time
            self.max_time_2 = max(self.max_time_2, my_time)
            self.time_2.append(my_time)
        
        if self.cnt ==  2 * TCAM_SIZE + 100 :
            print(len(self.time_1))
            print(max(self.time_1))
            #self.tot_time_1 -= max(self.time_1)
            #self.time_1.remove(max(self.time_1))	
            print(max(self.time_1))
            print(len(self.time_1))
            print("average time of phase 1:", self.tot_time_1 / len(self.time_1))
            print("max time of phase 1:", self.max_time_1)
            print("modify max time of phase 1:", max(self.time_1))
            print("variance of phase 1:", numpy.var(self.time_1))
            print("max 10 of phase 1: ", self.max_n(self.time_1,50))
            print(len(self.time_2))
            print(max(self.time_2))
            #self.tot_time_2 -= max(self.time_2)
            #self.time_2.remove(max(self.time_2))
            print(len(self.time_2))
            print(max(self.time_2))
            print("average time of phase 2:", self.tot_time_2 /len(self.time_2))
            print("max time of phase 2:", self.max_time_2)
            print("modify max time of phase 2:", max(self.time_2))
            print("variance of phase 2:", numpy.var(self.time_2))
            print("max 10 of phase 2: ", self.max_n(self.time_2,10))
            exit(0)
            return

        datapath = ev.msg.datapath
        self.solve_operation(self.operations[self.cnt + self.base], datapath)
        self.cnt += 1
        self.send_barrier_request(datapath)

        
    # 实验写在这里
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.del_all(datapath)

        # to use rusen, fill the tcam with placeholder
        if ALGORITHM_OPTION != 1:
            self.base = TCAM_SIZE
            for i in range(0, TCAM_SIZE):
                self.solve_operation(self.operations[i], datapath)
        time.sleep(10)
        self.send_barrier_request(datapath)
        print("send barrier request")


    def add_flow(self, datapath, priority, match, actions, buffer_id = None, cookie = 0):
        #print("add flow!")
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
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
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
