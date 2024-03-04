from cmath import pi
import copy
import ipaddress
from math import fabs
import pickle
import sys
import numpy as np
import random
import time

# Part 0: parameter and const

RULESET_NAME = "MyRules15k_300.in"
MESSAGE_COST = 10000
TCAM_SIZE = 400
MAX_PRIORITY = 65535
# 1: direct  2: chain  3: fastup  4: pot
ALGORITHM_OPTION = 2

PLACEHOLDER = {}
PLACEHOLDER["src_ip"] = ipaddress.ip_address("192.168.1.1")
PLACEHOLDER["src_ip_mask"] = ipaddress.ip_address("255.255.255.255")
PLACEHOLDER["dst_ip"] = ipaddress.ip_address("192.168.1.1")
PLACEHOLDER["dst_ip_mask"] = ipaddress.ip_address("255.255.255.255")
PLACEHOLDER["src_p"] = 0
PLACEHOLDER["dst_p"] = 0

random.seed(998244353)

# Part 1: data structure

# need to change the rule pos in algorithm, so have to use global varible
rules = []

class Result(object):
    insert_num = 0
    delete_num = 0
    move_num = 0
    
    def output(self):
        print("end")
        if ALGORITHM_OPTION == 1:
            print("direct statistics result:")
        elif ALGORITHM_OPTION == 2:
            print("chain statistics result:")
        elif ALGORITHM_OPTION == 3:
            print("fastup statistics result:")
        else:
            print("pot statistics result:")
        print("acl1 -1 0 0 message_cost =", MESSAGE_COST)
        print("insert num: ", self.insert_num)
        print("delete num: ", self.delete_num)
        print("move num: ", self.move_num)


class TcamEntry(object):
    def __init__(self, empty, priority, rule):
        # empty: -1 means placeholder, 0 means not empty, 1 means empty
        # so use != 0 instead of == 1 to find an empty entry
        self.empty = empty
        self.priority = priority
        self.rule = rule
    
def tcam_copy(new_entry, old_entry):
    new_entry.empty = 0
    new_entry.rule = old_entry.rule
    new_entry.priority = old_entry.priority


# Part 2: rule parse and graph build

def is_overlap(r1,r2):
    if(r1["src_ip_net"][-1] < r2["src_ip_net"][0] or r1["src_ip_net"][0] > r2["src_ip_net"][-1]):
        return False
    if(r1["dst_ip_net"][-1] < r2["dst_ip_net"][0] or r1["dst_ip_net"][0] > r2["dst_ip_net"][-1]):
        return False
    return True

def ruleset_parser(ruleset_name):
    f = open(ruleset_name)
    line = f.readline()
    tmp_rule = {}
    cnt = 1
    while line:
        l = l = line.split()
        tmp_rule["src_ip"] = ipaddress.ip_address(l[0])
        tmp_rule["src_ip_mask"] = ipaddress.ip_address(l[1])
        tmp_rule["src_ip_net"] = ipaddress.ip_network(l[2])
        tmp_rule["dst_ip"] = ipaddress.ip_address(l[3])
        tmp_rule["dst_ip_mask"] = ipaddress.ip_address(l[4])
        tmp_rule["dst_ip_net"] = ipaddress.ip_network(l[5])
        tmp_rule["src_p"] = 0
        tmp_rule["dst_p"] = 0
        tmp_rule["proto"] = 6
        tmp_rule["prior"] = MAX_PRIORITY - cnt
        tmp_rule["in"] = []
        tmp_rule["out"] = []
        tmp_rule["pos"] = -1
        cnt += 1
        rules.append(copy.deepcopy(tmp_rule))
        line = f.readline()
    f.close()

    #random.shuffle(rules)

    rule_num = min(2 * TCAM_SIZE, len(rules))
    for i in range(rule_num):
        rules[i]["id"] = i
        for j in range(i + 1, rule_num):
            if is_overlap(rules[i], rules[j]):
                rules[i]["out"].append(rules[j])
                rules[j]["in"].append(rules[i])

    return rules



# Part 3: Rusen

openflow_buffer = []

def openflow_insert(rule, priority):
    openflow = {}
    # type 0 means insert and type 1 means delete
    openflow["type"] = 0
    openflow["src_ip"] = rule["src_ip"]
    openflow["src_ip_mask"] = rule["src_ip_mask"]
    openflow["dst_ip"] = rule["dst_ip"]
    openflow["dst_ip_mask"] = rule["dst_ip_mask"]
    openflow["src_p"] = rule["src_p"]
    openflow["dst_p"] = rule["dst_p"]
    openflow["priority"] = priority
    openflow_buffer.append(copy.deepcopy(openflow))
    return

def openflow_delete(rule, priority):
    openflow = {}
    # type 0 means insert and type 1 means delete
    openflow["type"] = 1
    openflow["src_ip"] = rule["src_ip"]
    openflow["src_ip_mask"] = rule["src_ip_mask"]
    openflow["dst_ip"] = rule["dst_ip"]
    openflow["dst_ip_mask"] = rule["dst_ip_mask"]
    openflow["src_p"] = rule["src_p"]
    openflow["dst_p"] = rule["dst_p"]
    openflow["priority"] = priority
    openflow_buffer.append(copy.deepcopy(openflow))
    return

def clear_buffer():
    for i in range(0, len(openflow_buffer), 1):
        openflow = openflow_buffer[i]
        if openflow["type"] == 1:
            print("delete", openflow["src_ip"], openflow["src_ip_mask"], 
                            openflow["dst_ip"], openflow["dst_ip_mask"], 
                            openflow["src_p"], openflow["dst_p"], openflow["priority"])
        else:
            print("insert", openflow["src_ip"], openflow["src_ip_mask"], 
                            openflow["dst_ip"], openflow["dst_ip_mask"], 
                            openflow["src_p"], openflow["dst_p"], openflow["priority"])
    openflow_buffer.clear()
    print("clear")


def subproblem_solve(tcam, result, start, end, flag):
    # use dependency_based
    if flag == -1:
        rule = rules[tcam[start].rule]
        tcam[end].empty = 0
        tcam[end].rule = rule["id"]
        rule["pos"] = end
        openflow_insert(rule, tcam[end].priority)
        # set the start tcam as empty
        openflow_delete(rules[tcam[start].rule], tcam[start].priority)
        tcam[start].empty = 1
        tcam[start].rule = -1
        result.insert_num += 1
        result.delete_num += 1
    else:
        if start < end:
            for i in range(end, start, -1):
                tcam_copy(tcam[i], tcam[i - 1])
                rules[tcam[i].rule]["pos"] = i
        if start > end:
            for i in range(end, start, 1):
                tcam_copy(tcam[i], tcam[i + 1])
                rules[tcam[i].rule]["pos"] = i
        tcam[start].empty = 1
        tcam[start].priority = flag
        tcam[start].rule = -1
        result.move_num += abs(end - start)


def subproblem_choose(tcam, start, end, flag):
    db_cost = 2 * MESSAGE_COST
    pb_cost = abs(end - start)
    # try to use priority_based
    if pb_cost < db_cost:
        # if flag != -1, don't need a new priority
        if flag != -1:
            return 0
        priority = -1
        if start == 1:
            if tcam[start].priority + 1 < MAX_PRIORITY:
                priority = (tcam[start].priority + MAX_PRIORITY) // 2
        elif start == TCAM_SIZE:
            if tcam[start].priority > 1:
                priority = tcam[start].priority // 2
        elif start < end and tcam[start - 1].priority - 1 > tcam[start].priority:
            priority = (tcam[start - 1].priority + tcam[start].priority) // 2
        elif start > end and tcam[start + 1].priority + 1 < tcam[start].priority:
            priority = (tcam[start + 1].priority + tcam[start].priority) // 2
        if priority != -1:
            return priority
    # choose to use dependency_based
    return -1

def rusen_update(tcam, result, rule, path):
    if path == []:
        print("Fatal Error: Path is empty")
        exit(-1)
    end = len(path) - 1
    # choice = -1 means use dependency_based, else use priority_based
    # in priority_based, 0 means no operation, else choice is the new priority
    choice = []
    # flag = -1 means the inserted rule in subproblem need a priority
    flag = -1
    for i in range(0, end):
        flag = subproblem_choose(tcam, path[i], path[i + 1], flag)
        choice.append(flag)
    
    # firstly delete the placeholder in the end of path
    if tcam[path[end]].empty == -1:
        openflow_delete(PLACEHOLDER, tcam[path[end]].priority)
        result.delete_num += 1
    for i in range(end, 0, -1):
        subproblem_solve(tcam, result, path[i - 1], path[i], choice[i - 1])
    
    rule["pos"] = path[0]
    tcam[path[0]].rule = rule["id"]
    tcam[path[0]].empty = 0
    openflow_insert(rule, tcam[path[0]].priority)
    result.insert_num += 1


def rusen_move(tcam, result, path):
    if path == []:
        print("Fatal Error: Path is empty")
        exit(-1)
    end = len(path) - 1
    # choice = -1 means use dependency_based, else use priority_based
    # in priority_based, 0 means no operation, else choice is the new priority
    choice = []
    # flag = -1 means the inserted rule in subproblem need a priority
    flag = -1
    for i in range(0, end):
        flag = subproblem_choose(tcam, path[i], path[i + 1], flag)
        choice.append(flag)
    
    # firstly delete the placeholder in the end of path
    if tcam[path[i]].empty == -1:
        openflow_delete(PLACEHOLDER, tcam[path[i]].priority)
        result.delete_num += 1
    for i in range(end, 0, -1):
        subproblem_solve(tcam, result, path[i - 1], path[i], choice[i - 1])

    # maybe add a placeholder in the empty place
    # openflow_insert(PLACEHOLDER, tcam[path[0]].priority)
    # result.insert_num += 1



# Part 4: algorithm detail

# By default, the algorithm will use rusen
class algorithm(object):
    # each algorithm maintain its own Tcam and Result
    def __init__(self):
        self.tcam = []
        self.result = Result()
        delta = MAX_PRIORITY // TCAM_SIZE
        # use placeholder to fill the tcam
        for i in range(0, TCAM_SIZE + 1):
            priority = (TCAM_SIZE - i) * delta + 1
            self.tcam.append(TcamEntry(-1, priority, -1))
            if i != 0:
                openflow_insert(PLACEHOLDER, priority)
                clear_buffer()

    def delete(self, pos):
        if pos <= 0 or pos > TCAM_SIZE:
            print("Fatal error: Delete rule in wrong position")
            exit(-1)
        if self.tcam[pos].empty != 0:
            return
        openflow_delete(rules[self.tcam[pos].rule], self.tcam[pos].priority)
        rules[self.tcam[pos].rule]["pos"] = -1
        self.tcam[pos].rule = -1
        self.tcam[pos].empty = 1
        self.result.delete_num += 1
        # maybe add a placeholder in the empty place
        # openflow_insert(PLACEHOLDER, self.tcam[pos].priority)
        # self.result.insert_num += 1

    def linear_search_for_low_bound(self, rule):
        down_limit = TCAM_SIZE
        for r in rule["out"]:
            if r["pos"] != -1 and r["pos"] < down_limit:
                down_limit = r["pos"]
        return down_limit
    
    def linear_search_for_high_bound(self, rule):
        up_limit = -1
        for r in rule["in"]:
            if r["pos"] != -1 and r["pos"] > up_limit:
                up_limit = r["pos"]
        return up_limit

    def linear_search_for_empty_entry_below(self, pos):
        for i in range(1, TCAM_SIZE + 1):
            if self.tcam[i].empty != 0 and i >= pos:
                return i
        return TCAM_SIZE + 1
    
    def linear_search_for_empty_entry_above(self, pos):
        for i in range(TCAM_SIZE, 0, -1):
            if self.tcam[i].empty != 0 and i <= pos:
                return i
        return 0

    def reversal_judge(self, rule):
        pos_low = self.linear_search_for_low_bound(rule)
        pos_high = self.linear_search_for_high_bound(rule)
        if(pos_low < pos_high):
            return False
        else:
            return True

    def priority_reversal_elimination(self, rule):
        while not self.reversal_judge(rule):
            pos_low = self.linear_search_for_low_bound(rule)
            entry_below = self.linear_search_for_empty_entry_below(pos_low)
            down_path = []
            if (entry_below <= TCAM_SIZE):
                down_path = self.finding_path_down(pos_low, entry_below)
                rusen_move(self.tcam, self.result, down_path)
            else:
                print("Fatal error: Fail to eliminate reversal")
                exit(-1)
    
    def linear_search_for_empty_entry_interval(self, pos_high, pos_low):
        for i in range(1, TCAM_SIZE + 1):
            if self.tcam[i].empty != 0 and i > pos_high and i < pos_low:
                return i
        return 0

    def finding_path_up(self, start, end):
        path = []
        path.append(start)
        if start == end:
            return path
        start = self.linear_search_for_high_bound(rules[self.tcam[start].rule])
        while start > end:
            path.append(start)
            start = self.linear_search_for_high_bound(rules[self.tcam[start].rule])
        path.append(end)
        return path

    def finding_path_down(self, start, end):
        path = []
        path.append(start)
        if start == end:
            return path
        start = self.linear_search_for_low_bound(rules[self.tcam[start].rule])
        while start < end:
            path.append(start)
            start = self.linear_search_for_low_bound(rules[self.tcam[start].rule])
        path.append(end)
        return path



# the direct subclass don't use rusen
class direct(object):
    # each algorithm maintain its own Tcam and Result
    def __init__(self):
        self.tcam = []
        delta = MAX_PRIORITY // TCAM_SIZE
        for i in range(0, TCAM_SIZE + 1):
            self.tcam.append(TcamEntry(1, (TCAM_SIZE - i + 1) * delta, -1))
        self.result = Result()

    def delete(self, pos):
        if pos <= 0 or pos > TCAM_SIZE:
            print("Fatal error: Delete rule in wrong position")
            exit(-1)
        if self.tcam[pos].empty != 0:
            return
        openflow_delete(rules[self.tcam[pos].rule], self.tcam[pos].priority)
        rules[self.tcam[pos].rule]["pos"] = -1
        self.tcam[pos].rule = -1
        self.tcam[pos].empty = 1
        self.result.delete_num += 1

    def insert(self, rule):
        # insert the first rule in tcam
        if self.tcam[1].empty != 0:
            self.tcam[1].empty = 0
            self.tcam[1].rule = rule["id"]
            openflow_insert(rule, self.tcam[1].priority)
            self.result.insert_num += 1
            return
        
        # find an empty entry and move a segment of tcam
        empty_pos = 0
        aim_pos = 1
        for i in range(2, TCAM_SIZE + 1):
            if self.tcam[i].empty != 0 and empty_pos == 0:
                empty_pos = i
            if self.tcam[i].empty == 0 and self.tcam[i].priority > rule["prior"]:
                aim_pos = i
        if empty_pos == 0:
            print("Fatal error: TCAM is full!")
            exit(-1)
        openflow_insert(rule, rule["prior"])
        self.result.insert_num += 1
        if empty_pos < aim_pos:
            for i in range(empty_pos, aim_pos):
                tcam_copy(self.tcam[i], self.tcam[i + 1])
                rules[self.tcam[i].rule]["pos"] = i
        else:
            aim_pos += 1
            for i in range(empty_pos, aim_pos, -1):
                tcam_copy(self.tcam[i], self.tcam[i - 1])
                rules[self.tcam[i].rule]["pos"] = i
        self.tcam[aim_pos].rule = rule["id"]
        self.tcam[aim_pos].priority = rule["prior"]
        self.tcam[aim_pos].empty = 0
        self.result.move_num += abs(aim_pos - empty_pos)



class chain(algorithm):
    def __init__(self):
        self.tcam = []
        delta = MAX_PRIORITY // TCAM_SIZE
        for i in range(0, TCAM_SIZE + 1):
            self.tcam.append(TcamEntry(1, MAX_PRIORITY, -1))
        self.tcam.append(TcamEntry(1, 0, -1))
        self.result = Result()

    def delete(self, pos):
        if pos <= 0 or pos > TCAM_SIZE:
            print("Fatal error: Delete rule in wrong position")
            exit(-1)
        if self.tcam[pos].empty != 0:
            return
        openflow_delete(rules[self.tcam[pos].rule], self.tcam[pos].priority)
        rules[self.tcam[pos].rule]["pos"] = -1
        self.result.delete_num += 1

        # move the empty entry to top
        for j in range(pos, 0, -1):
            if self.tcam[j - 1].empty != 0:
                self.tcam[j].empty = 1
                break
            tcam_copy(self.tcam[j], self.tcam[j - 1])
            rules[self.tcam[j].rule]["pos"] = j
        

    def insert(self, rule):
        if not self.reversal_judge(rule):
            print("Reversal in Algorithm Chain")
            self.priority_reversal_elimination(rule)
        pos_low = self.linear_search_for_low_bound(rule)
        pos_high = self.linear_search_for_high_bound(rule)
        entry_above = 0
        for i in range(1, TCAM_SIZE):
            if self.tcam[i].empty == 0:
                entry_above = i
                break
        print("ea",entry_above)
        print("high",pos_high)
        print("low",pos_low)
        print(self.tcam[entry_above].priority)

        #insert the first rule
        if self.tcam[TCAM_SIZE-1].empty != 0:
            priority = MAX_PRIORITY // 10
            openflow_insert(rule, priority)
            aim_pos = TCAM_SIZE-1
            rule["pos"] = aim_pos
            self.tcam[aim_pos].rule = rule["id"]
            self.tcam[aim_pos].priority = priority
            self.tcam[aim_pos].empty = 0
            self.result.insert_num += 1
            return 1

        if pos_high == -1 and self.tcam[entry_above].priority != 65535:
            print("?")
            #priority = (self.tcam[entry_above].priority + MAX_PRIORITY+1) // 2
            priority = self.tcam[entry_above].priority + 100
            openflow_insert(rule, priority)
            rule["pos"] = entry_above-1
            self.tcam[entry_above-1].rule = rule["id"]
            self.tcam[entry_above-1].priority = priority
            self.tcam[entry_above-1].empty = 0
            self.result.insert_num += 1
            return 1

        pos_high = entry_above

        for i in range(pos_high,pos_low):
            if (self.tcam[i].priority - 1) != self.tcam[i + 1].priority:
                priority = (self.tcam[i].priority + self.tcam[i + 1].priority) // 2
                aim_pos = i
                for j in range(entry_above, aim_pos):
                    tcam_copy(self.tcam[j], self.tcam[j + 1])
                    rules[self.tcam[j].rule]["pos"] = j
                self.result.move_num += aim_pos - entry_above
                openflow_insert(rule, priority)
                rule["pos"] = aim_pos
                self.tcam[aim_pos].rule = rule["id"]
                self.tcam[aim_pos].priority = priority
                self.tcam[aim_pos].empty = 0
                self.result.insert_num += 1
                return 1
        # # no high bound
        # if pos_high == -1:
        #     pos_high = entry_above
        # if pos_low==401:
        #     priority = (65536+)

        # for i in range(entry_above,pos_high,-1):
        #     if self.tcam[i].priority - 1 != self.tcam[i - 1].priority:
        #         priority = (self.tcam[i].priority + self.tcam[i - 1].priority) // 2
        #         aim_pos = i
        #         # move the entries above the aim_pos
        #         for j in range(entry_above, aim_pos):
        #             tcam_copy(self.tcam[j], self.tcam[j + 1])
        #             rules[self.tcam[j].rule]["pos"] = j
        #         self.result.move_num += aim_pos - entry_above

        #         openflow_insert(rule, priority)
        #         rule["pos"] = aim_pos
        #         self.tcam[aim_pos].rule = rule["id"]
        #         self.tcam[aim_pos].priority = priority
        #         self.tcam[aim_pos].empty = 0
        #         self.result.insert_num += 1
        #         return 1
        
        print("FATAL: no enough priority!")
        return 0


class fastup(algorithm):
    def priority_reversal_elimination(self, rule):
        while not self.reversal_judge(rule):
            pos_low = self.linear_search_for_low_bound(rule)
            entry_below = self.linear_search_for_empty_entry_below(pos_low)
            pos_high = self.linear_search_for_high_bound(rule)
            entry_above = self.linear_search_for_empty_entry_above(pos_high)
            down_path = []
            up_path = []
            if entry_below <= TCAM_SIZE and entry_above > 0:
                down_path = self.finding_path_down(pos_low, entry_below)
                up_path = self.finding_path_up(pos_high, entry_above)
                if len(down_path) < len(up_path):
                    rusen_move(self.tcam, self.result, down_path)
                else:
                    rusen_move(self.tcam, self.result, up_path)
            elif entry_below <= TCAM_SIZE :
                down_path = self.finding_path_down(pos_low, entry_below)
                rusen_move(self.tcam, self.result, down_path)
            elif entry_above > 0 :
                up_path = self.finding_path_up(pos_high, entry_above)
                rusen_move(self.tcam, self.result, down_path)
            else:
                print("Fatal error: Fail to eliminate reversal")
                exit(-1)

    def cost_computing_down(self, pos_high, entry_below, pos_low):
        stack = []
        stack.append(entry_below)
        end_pos = 0
        i = entry_below - 1
        while i > pos_high:
            val = self.linear_search_for_low_bound(rules[self.tcam[i].rule])
            left = 0
            right = end_pos
            while left <= right:
                mid = (left + right) // 2
                if stack[mid] > val:
                    left = mid + 1
                else:
                    right = mid - 1

            if (left + 1) < len(stack):
                stack[left + 1] = i
            elif (left + 1) == len(stack):
                stack.append(i)
            else:
                print("Error: wrong in Cost_Computing_FastUp_Down!")
                exit(-1)
            end_pos = left + 1
            i = i - 1

        left = 0
        right = end_pos
        while left <= right:
            mid = (left + right) // 2
            if stack[mid] > pos_low:
                left = mid + 1
            else:
                right = mid - 1
        return stack[0 : left + 1]

    def cost_computing_up(self, pos_low, entry_above, pos_high):
        stack = []
        stack.append(entry_above)
        end_pos = 0
        i = entry_above + 1
        while i < pos_low:
            val = self.linear_search_for_high_bound(rules[self.tcam[i].rule])
            left = 0
            right = end_pos
            while left <= right:
                mid = (left + right) // 2
                if stack[mid] >= val:
                    right = mid - 1
                else:
                    left = mid + 1

            if (left + 1) < len(stack):
                stack[left + 1] = i
            elif (left + 1) == len(stack):
                stack.append(i)
            else:
                print("Error: wrong in Cost_Computing_FastUp_Up!")
                exit(-1)
            end_pos = left + 1
            i = i + 1
        # print("1 stack", stack[0 : end_pos + 1])
        left = 0
        right = end_pos
        while left <= right:
            mid = (left + right) // 2
            if stack[mid] >= pos_high:
                right = mid - 1
            else:
                left = mid + 1
        # print("2 stack", stack[0 : left + 1])
        return stack[0 : left + 1]

    def insert(self, rule):
        if not self.reversal_judge(rule):
            print("Reversal in Algorithm Fastup")
            self.priority_reversal_elimination(rule)

        pos_low = self.linear_search_for_low_bound(rule)
        pos_high = self.linear_search_for_high_bound(rule)
        empty_pos = self.linear_search_for_empty_entry_interval(pos_high, pos_low)

        if empty_pos != 0:
            path = []
            path.append(empty_pos)
            rusen_update(self.tcam, self.result, rule, path)
        else:
            entry_below = self.linear_search_for_empty_entry_below(pos_low)
            entry_above = self.linear_search_for_empty_entry_above(pos_high)
            if entry_below > TCAM_SIZE and entry_above <= 0:
                print("Fatal Error: TCAM is full!")
                exit(-1)

            stack_down = []
            stack_up = []
            if entry_below <= TCAM_SIZE:
                stack_down = self.cost_computing_down(pos_high, entry_below, pos_low)
                stack_down.reverse()

            if entry_above > 0:
                stack_up = self.cost_computing_up(pos_low, entry_above, pos_high)
                stack_up.reverse()

            if len(stack_down) == 0:
                rusen_update(self.tcam, self.result, rule, stack_up)
            elif len(stack_up) == 0:
                rusen_update(self.tcam, self.result, rule, stack_down)
            else:
                if(len(stack_up) < len(stack_down)):
                    rusen_update(self.tcam, self.result, rule, stack_up)
                else:
                    rusen_update(self.tcam, self.result, rule, stack_down)



class pot(algorithm):
    def cost_computing_down(self, pos_high, entry_below, pos_low):
        stack = []
        stack.append(entry_below)
        end_pos = 0
        i = entry_below - 1
        while i > pos_high:
            val = self.linear_search_for_low_bound(rules[self.tcam[i].rule])
            if stack[end_pos] < val:
                if end_pos + 1 == len(stack):
                    stack.append(i)
                else:
                    stack[end_pos + 1] = i
                end_pos += 1
            else:
                while stack[end_pos] >= val and end_pos > 0:
                    end_pos -= 1
                stack[end_pos] = i
            i = i - 1

        while end_pos > 0 and stack[end_pos] <= pos_low:
            end_pos -= 1

        return stack[0 : end_pos + 1]

    def cost_computing_up(self, pos_low, entry_above, pos_high):
        stack = []
        stack.append(entry_above)
        end_pos = 0
        i = entry_above + 1
        while i < pos_low:
            val = self.linear_search_for_high_bound(rules[self.tcam[i].rule])
            if stack[end_pos] < val:
                if end_pos + 1 == len(stack):
                    stack.append(i)
                else:
                    stack[end_pos + 1] = i
                end_pos += 1
            else:
                while stack[end_pos] >= val and end_pos > 0:
                    end_pos -= 1
                stack[end_pos] = i
            i = i + 1

        while end_pos > 0 and stack[end_pos] >= pos_high:
            end_pos -= 1

        return stack[0 : end_pos + 1]

    def insert(self, rule):
        if not self.reversal_judge(rule):
            print("Reversal in Algorithm Pot")
            self.priority_reversal_elimination(rule)

        pos_low = self.linear_search_for_low_bound(rule)
        pos_high = self.linear_search_for_high_bound(rule)
        empty_pos = self.linear_search_for_empty_entry_interval(pos_high, pos_low)

        if empty_pos != 0:
            path = []
            path.append(empty_pos)
            rusen_update(self.tcam, self.result, rule, path)
        else:
            entry_below = self.linear_search_for_empty_entry_below(pos_low)
            entry_above = self.linear_search_for_empty_entry_above(pos_high)
            if entry_below > TCAM_SIZE and entry_above <= 0:
                print("Fatal Error: TCAM is full!")
                exit(-1)

            stack_down = []
            stack_up = []
            if entry_below <= TCAM_SIZE:
                stack_down = self.cost_computing_down(pos_high, entry_below, pos_low)
                stack_down.reverse()

            if entry_above > 0:
                stack_up = self.cost_computing_up(pos_low, entry_above, pos_high)
                stack_up.reverse()

            # print("pot log! entry_below", entry_below, "entry_above", entry_above, "pos_low", pos_low, "pos_high", pos_high)
            # print("???", len(stack_up), len(stack_down))
            if len(stack_down) == 0:
                rusen_update(self.tcam, self.result, rule, stack_up)
            elif len(stack_up) == 0:
                rusen_update(self.tcam, self.result, rule, stack_down)
            else:
                if(len(stack_up) < len(stack_down)):
                    rusen_update(self.tcam, self.result, rule, stack_up)
                else:
                    rusen_update(self.tcam, self.result, rule, stack_down)



if __name__=="__main__":
    rules = ruleset_parser(RULESET_NAME)
    myin=0
    myout=0
    for i in rules:
        myin += len(i['in'])
        myout += len(i['out'])
    print(myin,myout)

    if ALGORITHM_OPTION == 1:
        my_algorithm = direct()
    elif ALGORITHM_OPTION == 2:
        my_algorithm = chain()
    elif ALGORITHM_OPTION == 3: 
        my_algorithm = fastup()
    else:
        my_algorithm = pot()

    start_time = time.time()

    i = 0
    cnt = 0
    while cnt < 0:
        if my_algorithm.insert(rules[i]) == 1:
            clear_buffer()
            cnt += 1
        i += 1

    while cnt < 2 * 0:
        j = random.randint(1, TCAM_SIZE)
        my_algorithm.delete(j)
        if my_algorithm.insert(rules[i]) == 1:
            clear_buffer()
            cnt += 1
        else:
            openflow_buffer.clear()
        i += 1

    my_algorithm.result.output()
    print(time.time() - start_time)
