# coding: utf-8

import json

from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import Response
from ryu.app.wsgi import WSGIApplication
from ryu.app.wsgi import route
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import packet
from ryu.ofproto import ofproto_v1_3

import network_awareness
import setting


# TrafficManager是RYU的基础撒谎嗯开发的基于带宽的最优路径应用，它通过模块网络感知和网络监控来完成最优路径计算。
class TrafficManager(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        "network_awareness": network_awareness.NetworkAwareness,
        'wsgi': WSGIApplication
    }

    def __init__(self, *args, **kwargs):
        super(TrafficManager, self).__init__(*args, **kwargs)
        self.name = 'traffic_manager'
        self.awareness = kwargs["network_awareness"]
        self.host_path = {}  # 所有主机连接服务器的路径{host_ip:[2,4,5]}
        self.datapaths = {}  # 所有交换机 {dpid:datapath}
        wsgi = kwargs['wsgi']
        wsgi.register(StatsController, {'info': self})

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
                self.awareness.graph.remove_node(datapath.id)

    # 处理packet_in消息。通过ARP学习主机连接信息access_table {(sw,port):(ip, mac)}。来自未知主机的第一个数据包必须是ARP
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        pkt = packet.Packet(msg.data)
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if isinstance(arp_pkt, arp.arp):
            self.logger.debug("【" + self.name + "】 ARP包处理")
            self.arp_forwarding(msg, arp_pkt.src_ip, arp_pkt.dst_ip)

        if isinstance(ip_pkt, ipv4.ipv4):
            self.logger.debug("【" + self.name + "】IPV4包处理")
            if len(pkt.get_protocols(ethernet.ethernet)):
                eth_type = pkt.get_protocols(ethernet.ethernet)[0].ethertype
                self.shortest_forwarding(msg, eth_type, ip_pkt.src, ip_pkt.dst)

    # 如果目的主机记录存在，则将ARP数据包发送到目的主机，否则，将其传递到未知访问端口。
    def arp_forwarding(self, msg, src_ip, dst_ip):
        datapath = msg.datapath
        ofproto = datapath.ofproto

        result = self.awareness.get_host_location(dst_ip)
        if result:  # 主机连接信息中的主机记录。
            datapath_dst, out_port = result[0], result[1]
            datapath = self.datapaths[datapath_dst]
            out = self._build_packet_out(datapath, ofproto.OFP_NO_BUFFER,
                                         ofproto.OFPP_CONTROLLER,
                                         out_port, msg.data)
            datapath.send_msg(out)
        else:
            self.flood(msg)

    # 构建数据包输出对象
    def _build_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        actions = []
        if dst_port:
            actions.append(datapath.ofproto_parser.OFPActionOutput(dst_port))

        msg_data = None
        if buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            if data is None:
                return None
            msg_data = data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=buffer_id,
            data=msg_data, in_port=src_port, actions=actions)
        return out

    # 将ARP数据包泛洪发送
    def flood(self, msg):
        datapath = msg.datapath
        ofproto = datapath.ofproto

        for dpid in self.awareness.access_ports:
            for port in self.awareness.access_ports[dpid]:
                if (dpid, port) not in self.awareness.access_table.keys():
                    datapath = self.datapaths[dpid]
                    out = self._build_packet_out(
                        datapath, ofproto.OFP_NO_BUFFER,
                        ofproto.OFPP_CONTROLLER, port, msg.data)
                    datapath.send_msg(out)

    # 将最优转发路径设置到交换机中
    def shortest_forwarding(self, msg, eth_type, ip_src, ip_dst):
        datapath = msg.datapath
        in_port = msg.match['in_port']

        result = self.get_sw(datapath.id, in_port, ip_src, ip_dst)
        if result:
            src_sw, dst_sw = result[0], result[1]
            if dst_sw:
                # 获取计算的路径
                path = self.get_path(src_sw, dst_sw)
                if len(path) >= 3:
                    print "[PATH]" + str(ip_src) + "<-->" + str(ip_dst) + ": " + str(path)
                    if ip_src == setting.SERVICE_IP:
                        self.host_path[ip_dst] = path
                    elif ip_dst == setting.SERVICE_IP:
                        self.host_path[ip_src] = path
                #self.logger.info("[PATH]%s<-->%s: %s" % (ip_src, ip_dst, path))
                flow_info = (eth_type, ip_src, ip_dst, in_port)
                # 将流条目安装到路径旁边的datapath中。
                self.install_flow(self.datapaths,
                              self.awareness.link_to_port,
                              self.awareness.access_table, path,
                              flow_info, msg.buffer_id, msg, msg.data)

    # 获取源和目的交换机
    def get_sw(self, dpid, in_port, src, dst):
        src_sw = None
        dst_sw = None

        # src_location = self.awareness.get_host_location(src)
        # if in_port in self.awareness.access_ports[dpid]:
        #     if (dpid, in_port) == src_location:
        #         src_sw = src_location[0]
        #     else:
        #         return None

        src_location = self.awareness.get_host_location(src)
        if src_location:
            src_sw = src_location[0]
        dst_location = self.awareness.get_host_location(dst)
        if dst_location:
            dst_sw = dst_location[0]
        return src_sw, dst_sw

    # 获取最优路径
    def get_path(self, src, dst):
        shortest_paths = self.awareness.shortest_paths

        # 因为在调用self.awareness.get_best_path_by_bw时会计算所有路径，所以我们只需要在一段时间内调用它一次，然后，我们就可以直接获取路径了。
        # try:
        #     # 如果路径存在，则返回它。
        #     path = self.awareness.best_paths.get(src).get(dst)
        #     return path
        # except:
        #     # 如果路径不存在，计算它，然后返回。
        #     result = self.awareness.get_best_path_by_bw(shortest_paths)
        #     paths = result
        #     best_path = paths.get(src).get(dst)
        #     return best_path
        path = None
        # print str(src) + ":" + str(dst)
        # print str(self.awareness.best_paths)
        if (src, dst) in self.awareness.best_paths:
            path = self.awareness.best_paths.get((src, dst))
        else:
            path = self.awareness.get_best_path_by_bw_ok(src, dst)
        return path


    # 安装往返的流程 path=[dpid1, dpid2...] flow_info=(eth_type, src_ip, dst_ip, in_port)
    def install_flow(self, datapaths, link_to_port, access_table, path, flow_info, buffer_id, msg,data=None):
        if path is None or len(path) == 0:
            self.logger.info("路径错误!")
            return
        # in_port = flow_info[3]
        # first_dp = datapaths[path[0]]
        # out_port = first_dp.ofproto.OFPP_LOCAL
        back_info = (flow_info[0], flow_info[2], flow_info[1])

        # inter_link
        if len(path) > 2:
            for i in xrange(1, len(path) - 1):
                port = self.get_port_pair_from_link(link_to_port,
                                                    path[i - 1], path[i])
                port_next = self.get_port_pair_from_link(link_to_port,
                                                         path[i], path[i + 1])
                if port and port_next:
                    src_port, dst_port = port[1], port_next[0]
                    datapath = datapaths[path[i]]
                    self.send_flow_mod(datapath, flow_info, src_port, dst_port)
                    self.send_flow_mod(datapath, back_info, dst_port, src_port)
                    if msg.datapath.id == datapath.id:
                        self.send_packet_out(datapath, buffer_id, src_port, dst_port, data)
                    # self.logger.debug("链接流安装")
        in_port = self.awareness.get_host_location(flow_info[1])[1]
        first_dp = datapaths[path[0]]
        out_port = first_dp.ofproto.OFPP_LOCAL

        if len(path) > 1:
            # 最后一个流条目：tor  - > host
            port_pair = self.get_port_pair_from_link(link_to_port,
                                                     path[-2], path[-1])
            if port_pair is None:
                self.logger.info("找不到端口")
                return
            src_port = port_pair[1]

            dst_port = self.get_port(flow_info[2], access_table)
            if dst_port is None:
                self.logger.info("找不到最后一个端口。")
                return

            last_dp = datapaths[path[-1]]
            self.send_flow_mod(last_dp, flow_info, src_port, dst_port)
            self.send_flow_mod(last_dp, back_info, dst_port, src_port)
            if msg.datapath.id == last_dp.id:
                self.send_packet_out(last_dp, buffer_id, src_port, dst_port, data)

            # 第一个流入
            port_pair = self.get_port_pair_from_link(link_to_port,
                                                     path[0], path[1])
            if port_pair is None:
                self.logger.info("在第一跳中找不到端口.")
                return
            out_port = port_pair[0]
            self.send_flow_mod(first_dp, flow_info, in_port, out_port)
            self.send_flow_mod(first_dp, back_info, out_port, in_port)
            #self.send_packet_out(first_dp, buffer_id, in_port, out_port, data)
            if msg.datapath.id == first_dp.id:
                self.send_packet_out(first_dp, buffer_id, in_port, out_port, data)
        # 源地址和目的地址在同一个datapath上
        else:
            out_port = self.get_port(flow_info[2], access_table)
            if out_port is None:
                self.logger.info("在同一个datapath中输出端口为None")
                return
            self.send_flow_mod(first_dp, flow_info, in_port, out_port)
            self.send_flow_mod(first_dp, back_info, out_port, in_port)
            self.send_packet_out(first_dp, buffer_id, in_port, out_port, data)

    # 获取端口对的链接，以便控制器可以安装流量条目。
    def get_port_pair_from_link(self, link_to_port, src_dpid, dst_dpid):
        if (src_dpid, dst_dpid) in link_to_port:
            return link_to_port[(src_dpid, dst_dpid)]
        else:
            # self.logger.info("dpid:%s->dpid:%s 是没有链接的" % (src_dpid, dst_dpid))
            return None

    # 生成流表并发送给交换机.
    def send_flow_mod(self, datapath, flow_info, src_port, dst_port):
        parser = datapath.ofproto_parser
        actions = []
        actions.append(parser.OFPActionOutput(dst_port))

        match = parser.OFPMatch(
            in_port=src_port, eth_type=flow_info[0],
            ipv4_src=flow_info[1], ipv4_dst=flow_info[2])

        self.add_flow(datapath, 1, match, actions,
                      idle_timeout=15, hard_timeout=60)

    # 将流表发送给交换机
    def add_flow(self, dp, p, match, actions, idle_timeout=0, hard_timeout=0):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=dp, priority=p,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        dp.send_msg(mod)

    # 获取目的主机连接交换机的端口 access_table: {(sw,port) :(ip, mac)}
    def get_port(self, dst_ip, access_table):
        if access_table:
            if isinstance(access_table.values()[0], tuple):
                for key in access_table.keys():
                    if dst_ip == access_table[key][0]:
                        dst_port = key[1]
                        return dst_port
        return None

    # 发送packet_out消息到交换机
    def send_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        out = self._build_packet_out(datapath, buffer_id,
                                     src_port, dst_port, data)
        if out:
            datapath.send_msg(out)


class StatsController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(StatsController, self).__init__(req, link, data, **config)
        self.info = data['info']

    @route('api', '/state', methods=['GET'])
    def get_state(self, req, **kwargs):
        return Response(content_type='application/json', body=json.dumps(True))

    @route('api', '/switches/desc', methods=['GET'])
    def get_switches_desc(self, req, **kwargs):
        result = []
        for dpid in self.info.awareness.port_speed:
            for port in self.info.awareness.port_speed[dpid]:
                capacity = setting.ORDINARY_BANDWIDTH
                if dpid in setting.SWITCHS and port in self.info.awareness.gigabit_bandwidth_ports[dpid]:
                    capacity = setting.WIDE_BANDWIDTH
                result.append({"dpid": dpid, "port": port, "bandwidth": capacity - self.info.awareness.port_speed[dpid][port] * 8,
                               "speed": self.info.awareness.port_speed[dpid][port],
                               "capacity": capacity})
        body = json.dumps(result)
        return Response(content_type='application/json', body=body)

    @route('api', '/switches', methods=['GET'])
    def get_switches(self, req, **kwargs):
        return self._switches(req, **kwargs)

    @route('api', '/hosts', methods=['GET'])
    def get_hosts(self, req, **kwargs):
        return self._hosts(req, **kwargs)

    @route('api', '/hostpath', methods=['GET'])
    def get_host_path(self, req, **kwargs):
        result = []
        for ip in self.info.host_path:
            path = {"ip_src": ip, "ip_dst": setting.SERVICE_IP, "path": str(self.info.host_path[ip])}
            result.append(path)
        body = json.dumps(result)
        return Response(content_type='application/json', body=body)

    @route('api', '/link_num', methods=['GET'])
    def get_link_num(self, req, **kwargs):
        body = json.dumps(self.info.awareness.graph.number_of_edges())
        return Response(content_type='application/json', body=body)

    @route('api', '/link_info', methods=['GET'])
    def get_link_info(self, req, **kwargs):
        result = []
        for key in self.info.awareness.link_to_port:
            link = {"src": key[0], "src_prot": self.info.awareness.link_to_port[key][0], "dsc": key[1],
                    "dsc_prot": self.info.awareness.link_to_port[key][1],
                    "speed": max(self.info.awareness.port_speed[key[0], self.info.awareness.link_to_port[key][0]][-1],
                                 self.info.awareness.port_speed[key[1], self.info.awareness.link_to_port[key][1]][-1])}
            result.append(link)
        for tup in sorted(self.info.awareness.access_table):
            link = {"src": tup[0], "src_prot": tup[1], "dsc": self.info.awareness.access_table[tup][0],
                    "dsc_prot": "", "speed": self.info.awareness.port_speed[tup[0], tup[1]][-1]}
            result.append(link)
        body = json.dumps(result)
        return Response(content_type='application/json', body=body)

    def _switches(self, req, **kwargs):
        result = []
        for dpip in sorted(self.info.awareness.switch_port_table):
            switch = {"dpip": dpip, "ports": str(self.info.awareness.switch_port_table[dpip])}
            result.append(switch)
        body = json.dumps(result)
        return Response(content_type='application/json', body=body)

    def _hosts(self, req, **kwargs):
        result = []
        for tup in sorted(self.info.awareness.access_table):
            host = {"ipv4": self.info.awareness.access_table[tup][0], "mac": self.info.awareness.access_table[tup][1],
                    "switch": tup[0], "port": tup[1]}
            result.append(host)
        body = json.dumps(result)
        return Response(content_type='application/json', body=body)
