from scapy.all import rdpcap, Ether
from collections import defaultdict

# 固定输入
pcap_file = "Change VLAN（EC220-G5).pcapng"
mac_address = "3c:84:6a:6a:7f:f0"

def extract_lcp_echo_requests_and_replies(pcap_file, mac_address):
    packets = rdpcap(pcap_file)
    lcp_echo_requests = defaultdict(list)
    lcp_echo_replies = defaultdict(list)

    for idx, pkt in enumerate(packets):
        if Ether in pkt:
            eth = pkt[Ether]
            eth_payload = bytes(pkt[Ether])

            if len(eth_payload) < 30:
                continue

            pppoe_type = eth_payload[12:14]
            if pppoe_type != b'\x88\x64':
                continue

            code = eth_payload[22]
            identifier = eth_payload[23]

            if eth.src.lower() == mac_address.lower() and code == 0x09:
                print(f"[Request] No.{idx + 1}, ID={identifier}")
                lcp_echo_requests[identifier].append((idx + 1, identifier))

            elif eth.dst.lower() == mac_address.lower() and code == 0x0a:
                print(f"[Reply] No.{idx + 1}, ID={identifier}")
                lcp_echo_replies[identifier].append((idx + 1, identifier))

    return lcp_echo_requests, lcp_echo_replies

def match_echo_pairs(requests_dict, replies_dict):
    matched_count = 0
    unmatched_requests = []

    for identifier in requests_dict:
        req_list = requests_dict[identifier]
        rep_list = replies_dict.get(identifier, [])

        pair_count = min(len(req_list), len(rep_list))

        for i in range(pair_count):
            req_no = req_list[i][0]
            rep_no = rep_list[i][0]
            matched_count += 1
            print(f"✅ 匹配成功：Request No. {req_no} <=> Reply No. {rep_no}")

        for i in range(pair_count, len(req_list)):
            unmatched_requests.append(req_list[i][0])

    return matched_count, unmatched_requests

def main():
    req_dict, rep_dict = extract_lcp_echo_requests_and_replies(pcap_file, mac_address)
    matched_count, unmatched = match_echo_pairs(req_dict, rep_dict)

    print(f"\n✅ 匹配成功的 LCP Echo Request/Reply 对数：{matched_count}")
    print(f"❌ 没有匹配到 Echo Reply 的 Echo Request 数量：{len(unmatched)}")

    if unmatched:
        print("\n未匹配 Echo Reply 的 Request 报文编号：")
        for no in unmatched:
            print(f"- Request No. {no}")

    # 添加结论输出
    if len(unmatched) > 3:
        print("\n⚠️ 结论：这个报文里可能存在 LCP 保活超时的可能")
    else:
        print("\n✅ 结论：暂时没发现PPPoE相关的异常")

if __name__ == "__main__":
    main()
