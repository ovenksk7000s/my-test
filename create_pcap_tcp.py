import json
import os
from scapy.all import *

def create_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload=b''):
    # 构造以太网头
    eth_dst = "ff:ff:ff:ff:ff:ff"  # 广播地址
    eth_src = "12:34:56:78:9a:bc"  # 源 MAC 地址
    eth_type = 0x86dd if ':' in src_ip else 0x0800  # IPv6 或 IPv4

    ethernet_frame = Ether(dst=eth_dst, src=eth_src, type=eth_type)

    # 构造 IP 头
    if ':' in src_ip:  # 如果是IPv6
        ip_header = IPv6(src=src_ip, dst=dst_ip)
    else:  # 如果是IPv4
        ip_header = IP(src=src_ip, dst=dst_ip)

    # 构造 TCP 头
    tcp_header = TCP(sport=src_port, dport=dst_port, seq=seq, ack=ack, flags=flags)

    # 创建完整的 TCP 报文
    tcp_packet = ethernet_frame / ip_header / tcp_header / Raw(load=payload)

    return tcp_packet

def write_to_pcap(packets, filename):
    # 将构造的报文写入 PCAP 文件
    wrpcap(filename, packets)
    print(f"已将报文写入 {filename}")

def build_tcp_handshake_data_teardown(src_ip, dst_ip, src_port, dst_port, payload):
    packets = []

    # 三次握手
    seq_client = 1000
    seq_server = 2000

    # SYN
    syn_packet = create_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq=seq_client, ack=0, flags='S')
    packets.append(syn_packet)

    # SYN-ACK
    syn_ack_packet = create_tcp_packet(dst_ip, src_ip, dst_port, src_port, seq=seq_server, ack=seq_client + 1, flags='SA')
    packets.append(syn_ack_packet)

    # ACK
    ack_packet = create_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq=seq_client + 1, ack=seq_server + 1, flags='A')
    packets.append(ack_packet)

    # 带负载的数据包
    data_packet = create_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq=seq_client + 1, ack=seq_server + 1, flags='A', payload=payload)
    packets.append(data_packet)

    # ACK 确认数据包
    ack_data_packet = create_tcp_packet(dst_ip, src_ip, dst_port, src_port, seq=seq_server + 1, ack=seq_client + 1 + len(payload), flags='A')
    packets.append(ack_data_packet)

    # 四次挥手
    # FIN 从客户端发起
    fin_packet = create_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq=seq_client + 1 + len(payload), ack=seq_server + 1, flags='F')
    packets.append(fin_packet)

    # ACK
    ack_fin_packet = create_tcp_packet(dst_ip, src_ip, dst_port, src_port, seq=seq_server + 1, ack=seq_client + 2 + len(payload), flags='A')
    packets.append(ack_fin_packet)

    # FIN 从服务器发起
    fin_packet_2 = create_tcp_packet(dst_ip, src_ip, dst_port, src_port, seq=seq_server + 1, ack=seq_client + 2 + len(payload), flags='F')
    packets.append(fin_packet_2)

    # ACK
    ack_fin_packet_2 = create_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq=seq_client + 2 + len(payload), ack=seq_server + 2, flags='A')
    packets.append(ack_fin_packet_2)

    return packets

def main(config_file):
    with open(config_file, 'r', encoding='utf-8') as f:
        config = json.load(f)

    output_dir = config.get("output_dir", "output")  # 获取输出目录, 默认值为 "output"
    os.makedirs(output_dir, exist_ok=True)  # 创建输出目录（如果不存在）

    for idx, connection in enumerate(config["connections"]):
        file_path = connection["file_path"]
        src_ip = connection["src_ip"]
        dst_ip = connection["dst_ip"]
        src_port = connection["src_port"]
        dst_port = connection["dst_port"]
        # payload = connection["payload"].encode('utf-8')  # 将字符串转换为字节
        payload = bytes.fromhex(connection["payload"])
        # 生成 TCP 报文和握手、数据传输、挥手包
        packets = build_tcp_handshake_data_teardown(src_ip, dst_ip, src_port, dst_port, payload)

        # 定义 PCAP 文件名
        pcap_filename = os.path.join(output_dir, f"{file_path}.pcap")
        # 写入到 PCAP 文件
        write_to_pcap(packets, pcap_filename)

if __name__ == "__main__":
    config_file = "tcp_config.json"  # 配置文件路径
    main(config_file)