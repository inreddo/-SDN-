# coding: utf-8

import copy
from operator import attrgetter

import networkx as nx
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import packet
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event
from ryu.topology.api import get_switch, get_link

import setting


class NetworkAwareness(app_manager.RyuApp):
    """
        NetworkAwareness是一个用于发现网络信息的Ryu模块。
        此模块可以为其他模块或应用提供许多数据服务，例如:
        交换机的链路信息，主机的连接信息，交换机端口，连接主机的交换机端口信息，连接集交换机的交换机端口信息、拓扑图和最短路径。
    """

    # 设置OpenFlow协议版本为1.3
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(NetworkAwareness, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        self.name = "awareness"
        self.link_to_port = {}  # 交换机链路 {(src_dpid,dst_dpid):(src_port,dst_port)}
        self.access_table = {}  # 主机链路 {(sw,port):(ip, mac)}
        self.switch_port_table = {}  # 交换机全部端口表 {dpid:[1,2,..])}
        self.access_ports = {}  # 主机访问端口表 {dpid:[1,2,..]}
        self.interior_ports = {}  # 交换机连接端口表 {dpid:[1,2,..])}
        self.million_gigabit_bandwidth_link = {}  # 万兆带宽链路 {(src_dpid,dst_dpid):(src_port,dst_port)}

        self.graph = nx.DiGraph()  # 网络图
        self.pre_graph = nx.DiGraph()  # 旧网络图
        self.pre_access_table = {}  # 旧主机链路
        self.pre_link_to_port = {}  # 旧交换机链路
        self.shortest_paths = None  # 最短路径 {1: {1: [[1], [1]], 2: [[1, 2], [1, 3, 2]],..}
        self.switches = None  # 所有交换机
        self.discover_thread = hub.spawn(self.discover)  # 发现网络资源

        self.datapaths = {}  # 所有交换机 {dpid:datapath}
        self.port_stats = {}  # 端口统计信息 {(dpid, port_no):(tx_bytes, rx_bytes,rx_errors,duration_sec, duration_nsec)}
        self.port_speed = {}  # 端口速度 {(dpid, port_no):[1,2,..]} MB/s
        self.port_features = {}  # 端口状态描述信息 {dpid:{port_no:(config, state, curr_speed)}}
        self.free_bandwidth = {}  # 剩余带宽{dpid:{port_no:free_bw}} Mbit/s
        self.best_paths = {}  # 最优路径
        self.monitor_thread = hub.spawn(self.monitor)  # 流量监控

    # 周期获取拓扑信息
    def discover(self):
        while True:
            hub.sleep(setting.DISCOVERY_PERIOD)
            self.get_topology(None)
            if setting.TOSHOW:
                self.show_topology()

    # 根据事件变化获取拓扑信息并计算最短路径
    @set_ev_cls([event.EventSwitchEnter, event.EventSwitchLeave,  # 交换机加入和离开
                 event.EventPortAdd, event.EventPortDelete, event.EventPortModify,  # 交换机端口添加，修改和删除
                 event.EventLinkAdd, event.EventLinkDelete])  # 链接添加和删除
    def get_topology(self, event):
        # 获取所有交换机
        switch_list = get_switch(self.topology_api_app, None)
        self.create_port_map(switch_list)
        self.switches = self.switch_port_table.keys()
        # 获取链接信息
        links = get_link(self.topology_api_app, None)
        self.create_interior_links(links)
        self.create_access_ports()
        self.get_graph(self.link_to_port.keys())
        self.shortest_paths = self.all_k_shortest_paths(self.graph, weight='weight', k=setting.K_PATHS)

    # 创建交换机全部端口表，交换机连接端口表和主机访问端口表
    def create_port_map(self, switch_list):
        for sw in switch_list:
            dpid = sw.dp.id
            # 交换机全部端口表
            self.switch_port_table.setdefault(dpid, set())
            for port in sw.ports:
                self.switch_port_table[dpid].add(port.port_no)

            # 交换机连接端口表，但链接链接端口为空
            self.interior_ports.setdefault(dpid, set())
            # 主机访问端口表，但链接链接端口为空
            self.access_ports.setdefault(dpid, set())

    # 创建交换机链路 {(src_dpid,dst_dpid):(src_port,dst_port)}
    def create_interior_links(self, link_list):
        for link in link_list:
            src = link.src
            dst = link.dst
            self.link_to_port[(src.dpid, dst.dpid)] = (src.port_no, dst.port_no)
            if src.dpid in setting.SWITCHS and dst.dpid in setting.SWITCHS:
                self.million_gigabit_bandwidth_link[(src.dpid, dst.dpid)] = (src.port_no, dst.port_no)

            # 在交换机连接端口表中添加端口
            if link.src.dpid in self.switches:
                self.interior_ports[link.src.dpid].add(link.src.port_no)
            if link.dst.dpid in self.switches:
                self.interior_ports[link.dst.dpid].add(link.dst.port_no)

    # 创建主机访问端口表 {dpid:set(port_num)}
    def create_access_ports(self):
        for sw in self.switch_port_table:
            all_port_table = self.switch_port_table[sw]
            interior_port = self.interior_ports[sw]
            self.access_ports[sw] = all_port_table - interior_port

    # 使用link_list构建网络图
    def get_graph(self, link_list):
        for src in self.switches:
            for dst in self.switches:
                if src == dst:
                    self.graph.add_edge(src, dst, weight=0)
                elif (src, dst) in link_list:
                    self.graph.add_edge(src, dst, weight=1)
        return self.graph

    # 获取所有节点之间的K条最短路径
    def all_k_shortest_paths(self, graph, weight='weight', k=1):
        _graph = copy.deepcopy(graph)
        paths = {}  # {src:{dst:[[3,5,6],..,[2,5,8]]}},[3,5,6]为路径

        # 在图中找到k条最短路径
        for src in _graph.nodes():
            paths.setdefault(src, {src: [[src] for i in xrange(k)]})
            for dst in _graph.nodes():
                if src == dst:
                    continue
                paths[src].setdefault(dst, [])
                paths[src][dst] = self.k_shortest_paths(_graph, src, dst, weight=weight, k=k)
        return paths

    # 创建K条src到dst的最短路径
    def k_shortest_paths(self, graph, src, dst, weight='weight', k=1):
        generator = nx.shortest_simple_paths(graph, source=src, target=dst, weight=weight)
        shortest_paths = []  # k条路径,从最短的开始
        try:
            for path in generator:
                # path = [1,5,6]
                if k <= 0:
                    break
                shortest_paths.append(path)
                k -= 1
            return shortest_paths
        except:
            self.logger.debug("%s 到 %s 之间没有路径" % (src, dst))

    # 处理交换机的Switch Features讯息
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath  # 获取交换机
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()  # 创建一个空的匹配规则
        # 在交换机上不缓存包，将收到的整个包发送至控制器
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)  # 下发流表

    # 添加流表
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    # Packet-In事件接收处理位置目的地的封包
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if arp_pkt:
            arp_src_ip = arp_pkt.src_ip
            mac = arp_pkt.src_mac
            # 添加主机连接信息
            self.register_access_info(datapath.id, in_port, arp_src_ip, mac)
        elif ip_pkt:
            ip_src_ip = ip_pkt.src
            eth = pkt.get_protocols(ethernet.ethernet)[0]
            mac = eth.src
            # 添加主机连接信息
            self.register_access_info(datapath.id, in_port, ip_src_ip, mac)
        else:
            pass

    # 将主机连接信息添加到主机链路中。
    def register_access_info(self, dpid, in_port, ip, mac):
        if in_port in self.access_ports[dpid]:
            if (dpid, in_port) in self.access_table:
                if self.access_table[(dpid, in_port)] == (ip, mac):
                    return
                else:
                    self.access_table[(dpid, in_port)] = (ip, mac)
                    return
            else:
                self.access_table.setdefault((dpid, in_port), None)
                self.access_table[(dpid, in_port)] = (ip, mac)
                return

    # 根据主机IP获取获取连接的交换机 access_table：{(sw,port) :[host_ip]}
    def get_host_location(self, host_ip):
        for key in self.access_table.keys():
            if self.access_table[key][0] == host_ip:
                return key
        # self.logger.info("【" + self.name + "】 找不到该主机：%s." % host_ip)
        return None

    # 获取所有交换机
    def get_switches(self):
        return self.switches

    # 获取所有交换机链路
    def get_links(self):
        return self.link_to_port

    # 流量监控
    def monitor(self):
        while True:
            hub.sleep(setting.MONITOR_PERIOD)
            for dp in self.datapaths.values():
                self.port_features.setdefault(dp.id, {})
                self.request_stats(dp)
            self.best_paths = {}
            if setting.TOSHOW:
                self.show_stat()

    # 发起端口数据统计请求，交由监听EventOFPPortStatsReply事件的方法(_port_stats_reply_handler)处理
    def request_stats(self, datapath):
        self.logger.debug('发起状态请求: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # 发起端口状态请求
        req = parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)
        # 发起端口统计请求
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    # 处理端口数据统计请求，计算端口的速度并保存。 free_bandwidth = {dpid:{port_no:free_bw}}
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        body = ev.msg.body  # 端口数据
        dpid = ev.msg.datapath.id
        self.free_bandwidth.setdefault(dpid, {})

        for stat in sorted(body, key=attrgetter('port_no')):
            port_no = stat.port_no
            if port_no != ofproto_v1_3.OFPP_LOCAL:
                key = (dpid, port_no)
                value = (stat.tx_bytes, stat.rx_bytes, stat.rx_errors,
                         stat.duration_sec, stat.duration_nsec)
                self.save_stats(self.port_stats, key, value, 5)
                # Rx Bytes // 接收到的字节数
                # Tx Bytes // 发送出去的字节数

                # 获取端口速度
                pre = 0  # 旧端口流量
                period = setting.MONITOR_PERIOD  # 监测周期
                tmp = self.port_stats[key]
                if len(tmp) > 1:
                    pre = tmp[-2][0] + tmp[-2][1]
                    period = self.get_period(tmp[-1][3], tmp[-1][4], tmp[-2][3], tmp[-2][4])

                speed = self.get_speed(self.port_stats[key][-1][0] + self.port_stats[key][-1][1], pre, period)
                self.save_stats(self.port_speed, key, speed, 5)
                self.save_free_bandwidth(dpid, port_no, speed)

    # 保存端口速度
    def save_stats(self, _dict, key, value, length=5):
        if key not in _dict:
            _dict[key] = []
        _dict[key].append(value)
        if len(_dict[key]) > length:
            _dict[key].pop(0)

    def get_period(self, n_sec, n_nsec, p_sec, p_nsec):
        return self.get_time(n_sec, n_nsec) - self.get_time(p_sec, p_nsec)

    def get_time(self, sec, nsec):
        return sec + nsec / (10 ** 9)

    # 计算带宽速度
    def get_speed(self, now, pre, period):
        if period:
            return ((now - pre) / period) / (1024 * 1024)
        else:
            return 0

    # 获取端口的空闲带宽。
    def save_free_bandwidth(self, dpid, port_no, speed):
        port_state = self.port_features.get(dpid).get(port_no)
        if port_state:
            capacity = setting.ORDINARY_BANDWIDTH
            if dpid in setting.SWITCHS:
                for key in self.million_gigabit_bandwidth_link:
                    if key[0] == dpid and self.million_gigabit_bandwidth_link[key][0] == port_no:
                        capacity = setting.WIDE_BANDWIDTH
            curr_bw = self.get_free_bw(capacity, speed)
            self.free_bandwidth[dpid].setdefault(port_no, None)
            self.free_bandwidth[dpid][port_no] = curr_bw
        else:
            self.logger.info("无法获取端口状态")

    # 计算剩余带宽
    def get_free_bw(self, capacity, speed):
        return max(capacity - speed * 8, 0)

    def get_best_path_by_bw_ok(self, sw_src,sw_dst):
        paths = copy.deepcopy(self.shortest_paths)  # best_paths = {1: {1: [[1], [1]], 2: [[1, 2], [1, 3, 2]],..}
        if sw_src == sw_dst:
            return [sw_dst]
        else:
            base_utilization = 100
            # 基础路径
            best_path = paths[sw_src][sw_dst][0]
            for path in paths[sw_src][sw_dst]:
                utilization = 0
                for i in xrange(len(path) - 1):
                    port = self.link_to_port[(path[i], path[i + 1])]
                    min_free_bandwidth = min(self.free_bandwidth[path[i]][port[0]],
                                             self.free_bandwidth[path[i + 1]][port[1]])
                    if path[i] in setting.SWITCHS and path[i + 1] in setting.SWITCHS:
                        utilization = 1 - min_free_bandwidth / setting.WIDE_BANDWIDTH + utilization + setting.WIDE_BANDWIDTH_FACTOR
                    else:
                        utilization = 1 - min_free_bandwidth / setting.ORDINARY_BANDWIDTH + utilization
                if base_utilization > utilization:
                    base_utilization = utilization
                    best_path = path
            # TODO 123
            if (sw_src, sw_dst) in self.best_paths:
                self.best_paths[(sw_src, sw_dst)] = best_path
            else:
                self.best_paths.setdefault((sw_src,sw_dst), None)
                self.best_paths[(sw_src, sw_dst)] = best_path
            return best_path

    # 交换机状态改变事件
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
                self.graph.remove_node(datapath.id)

    # 获取端口描述信息
    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        msg = ev.msg
        dpid = msg.datapath.id
        ofproto = msg.datapath.ofproto

        config_dict = {ofproto.OFPPC_PORT_DOWN: "Down",
                       ofproto.OFPPC_NO_RECV: "No Recv",
                       ofproto.OFPPC_NO_FWD: "No Farward",
                       ofproto.OFPPC_NO_PACKET_IN: "No Packet-in"}

        state_dict = {ofproto.OFPPS_LINK_DOWN: "Down",
                      ofproto.OFPPS_BLOCKED: "Blocked",
                      ofproto.OFPPS_LIVE: "Live"}

        for p in ev.msg.body:
            if p.config in config_dict:
                config = config_dict[p.config]
            else:
                config = "up"

            if p.state in state_dict:
                state = state_dict[p.state]
            else:
                state = "up"

            port_feature = (config, state, p.curr_speed)
            self.port_features[dpid][p.port_no] = port_feature

    # 显示统计信息
    def show_stat(self):
        print ("带宽信息")
        print ("交换机 \t 端口 \t 剩余带宽 \t 速度")
        for dpid in self.free_bandwidth:
            for port in self.free_bandwidth[dpid]:
                print("%s \t\t %s \t %s \t %s" % (
                    dpid, port, self.free_bandwidth[dpid][port], self.port_speed[dpid, port][-1]))

    # 为restful接口提供数据
    def get_stat(self):
        result = []
        for dpid in self.free_bandwidth:
            for port in self.free_bandwidth[dpid]:
                result.append([dpid, port, self.free_bandwidth[dpid][port], self.port_speed[dpid, port][-1]])
        return result

    # 控制台显示拓扑信息
    def show_topology(self):
        print("----------------- 交换机连接信息 ----------------")
        for i in self.graph.nodes():
            print("\t%d" % i),
        print("")
        for i in self.graph.nodes():
            print("%d" % i),
            for j in self.graph.nodes():
                if (i, j) in self.link_to_port.keys():
                    print("\t%s" % str(self.link_to_port[(i, j)])),
                else:
                    print("\t无链接"),
            print("")
        if self.pre_link_to_port != self.link_to_port:
            self.pre_link_to_port = copy.deepcopy(self.link_to_port)
        print("------------------ 主机连接信息 -----------------")
        if self.access_table.keys():
            print("交换机 \t 端口 \t 主机信息")
            for tup in sorted(self.access_table):
                print("%d \t %d \t %s" % (tup[0], tup[1], self.access_table[tup]))
        if self.pre_access_table != self.access_table:
            self.pre_access_table = copy.deepcopy(self.access_table)
