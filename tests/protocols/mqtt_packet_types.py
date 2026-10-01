from scapy.all import *
from scapy.contrib.mqtt import *

def generate_mqtt_v3_1_pcap():
    packets = []
    
    # Base port - incremented per packet pair to guarantee Wireshark 
    # sees fresh TCP streams and decodes every payload independently.
    base_port = 50000

    def get_c2s(stream_id):
        """Generates Client-to-Server TCP/IP headers."""
        return IP(dst="192.168.1.100", src="192.168.1.50") / TCP(sport=base_port + stream_id, dport=1883, flags="PA", seq=100)

    def get_s2c(stream_id):
        """Generates Server-to-Client TCP/IP headers."""
        return IP(dst="192.168.1.50", src="192.168.1.100") / TCP(sport=1883, dport=base_port + stream_id, flags="PA", seq=100)

    # ---------------------------------------------------------
    # 1. CONNECT (The Critical v3.1 Handshake)
    # We explicitly define protoname as "MQIsdp" and protolevel as 3.
    # We also keep the clientId short (under 23 bytes) to comply with v3.1 rules.
    # ---------------------------------------------------------
    pkt = get_c2s(1) / MQTT(type=1) / MQTTConnect(
        protoname=b"MQIsdp", 
        protolevel=3, 
        clientId=b"client_v3_basic", 
        cleansess=1, 
        klive=60
    )
    packets.append(pkt)

    # ---------------------------------------------------------
    # 2. CONNACK (Connection Acknowledgment)
    # ---------------------------------------------------------
    pkt = get_s2c(2) / MQTT(type=2) / MQTTConnack(sessPresentFlag=0, retcode=0)
    packets.append(pkt)

    # ---------------------------------------------------------
    # 3. PUBLISH (QoS 1)
    # ---------------------------------------------------------
    pkt = get_c2s(3) / MQTT(type=3, QOS=1) / MQTTPublish(topic=b"sensors/temp", msgid=10, value=b"22.5")
    packets.append(pkt)

    # ---------------------------------------------------------
    # 4. PUBACK (Publish Acknowledgment)
    # ---------------------------------------------------------
    pkt = get_s2c(4) / MQTT(type=4) / MQTTPuback(msgid=10)
    packets.append(pkt)

    # ---------------------------------------------------------
    # 5. PUBREC (Publish Received - QoS 2 Step 1)
    # ---------------------------------------------------------
    pkt = get_c2s(5) / MQTT(type=5) / MQTTPubrec(msgid=11)
    packets.append(pkt)

    # ---------------------------------------------------------
    # 6. PUBREL (Publish Release - QoS 2 Step 2)
    # ---------------------------------------------------------
    pkt = get_s2c(6) / MQTT(type=6) / MQTTPubrel(msgid=11)
    packets.append(pkt)

    # ---------------------------------------------------------
    # 7. PUBCOMP (Publish Complete - QoS 2 Step 3)
    # ---------------------------------------------------------
    pkt = get_c2s(7) / MQTT(type=7) / MQTTPubcomp(msgid=11)
    packets.append(pkt)

    # ---------------------------------------------------------
    # 8. SUBSCRIBE 
    # ---------------------------------------------------------
    pkt = get_c2s(8) / MQTT(type=8) / MQTTSubscribe(msgid=12, topics=[MQTTTopicQOS(topic=b"sensors/#", QOS=1)])
    packets.append(pkt)

    # ---------------------------------------------------------
    # 9. SUBACK (Subscribe Acknowledgment)
    # ---------------------------------------------------------
    pkt = get_s2c(9) / MQTT(type=9) / MQTTSuback(msgid=12, retcodes=[1])
    packets.append(pkt)

    # ---------------------------------------------------------
    # 10. UNSUBSCRIBE
    # ---------------------------------------------------------
    pkt = get_c2s(10) / MQTT(type=10) / MQTTUnsubscribe(msgid=13, topics=[MQTTTopic(topic=b"sensors/#")])
    packets.append(pkt)

    # ---------------------------------------------------------
    # 11. UNSUBACK (Unsubscribe Acknowledgment)
    # ---------------------------------------------------------
    pkt = get_s2c(11) / MQTT(type=11) / MQTTUnsuback(msgid=13)
    packets.append(pkt)

    # ---------------------------------------------------------
    # 12. PINGREQ (Ping Request)
    # ---------------------------------------------------------
    pkt = get_c2s(12) / MQTT(type=12)
    packets.append(pkt)

    # ---------------------------------------------------------
    # 13. PINGRESP (Ping Response)
    # ---------------------------------------------------------
    pkt = get_s2c(13) / MQTT(type=13)
    packets.append(pkt)

    # ---------------------------------------------------------
    # 14. DISCONNECT
    # ---------------------------------------------------------
    pkt = get_c2s(14) / MQTT(type=14) / MQTTDisconnect()
    packets.append(pkt)

    # Write all successfully crafted packets to a PCAP file
    file_name = "mqtt_v3_1_wireshark.pcap"
    wrpcap(file_name, packets)
    print(f"Successfully generated {len(packets)} isolated MQTT v3.1 packets to '{file_name}'!")

if __name__ == "__main__":
    generate_mqtt_v3_1_pcap()

