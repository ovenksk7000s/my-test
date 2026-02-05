import os
from scapy.all import *
import configparser

def create_udp_flow(src_ip, dst_ip, src_port, dst_port, request_payload, response_payload):
    # 构造以太网头
    eth_dst = "ff:ff:ff:ff:ff:ff"  # 广播地址
    eth_src = "12:34:56:78:9a:bc"  # 源 MAC 地址
    eth_type = 0x86dd if ':' in src_ip else 0x0800  # IPv6 或 IPv4
    
    ethernet_frame = Ether(dst=eth_dst, src=eth_src, type=eth_type)

    # 构造 IP 头
    if ':' in src_ip:  # IPv6
        ip_header_request = IPv6(src=src_ip, dst=dst_ip)
        ip_header_response = IPv6(src=dst_ip, dst=src_ip)
    else:  # IPv4
        ip_header_request = IP(src=src_ip, dst=dst_ip)
        ip_header_response = IP(src=dst_ip, dst=src_ip)

    # 构造 UDP 头
    udp_header_request = UDP(sport=src_port, dport=dst_port)
    udp_header_response = UDP(sport=dst_port, dport=src_port)

    # 创建完整的 UDP 请求报文
    udp_request = udp_header_request / Raw(load=request_payload)
    ip_request = ip_header_request / udp_request
    complete_request = ethernet_frame / ip_request

    # 创建完整的 UDP 响应报文
    udp_response = udp_header_response / Raw(load=response_payload)
    ip_response = ip_header_response / udp_response
    complete_response = ethernet_frame / ip_response

    return complete_request, complete_response

def write_to_pcap(flows, filename):
    # 将构造的请求和响应写入 PCAP 文件
    wrpcap(filename, flows)
    print(f"已将请求和响应写入 {filename}")

def read_config_file(filename):
    # 读取配置文件
    config = configparser.ConfigParser()
    with open(filename, 'r', encoding='utf-8') as configfile:  # 指定编码为 utf-8
        config.read_file(configfile)
    
    udp_settings = []
    output_directory = config['Settings']['output_directory']
    output_prefix = config['Settings']['output_prefix']
    
    for section in config.sections():
        if section.startswith("Flow_"):
            settings = {
                'src_ip': config[section]['src_ip'],
                'dst_ip': config[section]['dst_ip'],
                'src_port': int(config[section]['src_port']),
                'dst_port': int(config[section]['dst_port']),
                'request_payload': config[section]['request_payload'].encode(),
                'response_payload': config[section]['response_payload'].encode(),
                'output_file': os.path.join(output_directory, f"{output_prefix}{section}.pcap")  # 生成输出文件路径
            }
            udp_settings.append(settings)
    
    return udp_settings

if __name__ == "__main__":
    # 读取配置文件
    udp_settings = read_config_file('udp_flows_config.ini')

    # 创建输出目录（如果不存在）
    output_directory = os.path.dirname(udp_settings[0]['output_file'])  # 获取第一个流的输出文件路径获取目录
    os.makedirs(output_directory, exist_ok=True)

    for settings in udp_settings:
        request, response = create_udp_flow(
            settings['src_ip'],
            settings['dst_ip'],
            settings['src_port'],
            settings['dst_port'],
            settings['request_payload'],
            settings['response_payload']
        )
        
        # 写入 PCAP 文件
        write_to_pcap([request, response], settings['output_file'])