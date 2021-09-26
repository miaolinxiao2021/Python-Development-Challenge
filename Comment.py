import struct
import time

def timeTrans(GMTtime):
    timeArray = time.localtime(GMTtime)
    otherStyleTime = time.strftime("%Y--%m--%d %H:%M:%S", timeArray)
    return otherStyleTime
class PcapPacketHeader:
    def __init__(self):
        self.GMTtime = b'\x00\x00'
        self.microTime = b'\x00\x00'
        self.capLen = b'\x00\x00'
        self.len = b'\x00\x00'

if __name__ == '__main__':
    fPcap = open('stratosphere_capture_0x7.pcap','rb')
    fTxt = open('result.txt','w')

    data = fPcap.read()  #Read the Pcap file

    pcapHeader = {}
    pcapHeader['magic_number'] = data[0:4]
    pcapHeader['version_major'] = data[4:6]
    pcapHeader['version_minor'] = data[6:8]
    pcapHeader['thiszone'] = data[8:12]
    pcapHeader['sigfigs'] = data[12:16]
    pcapHeader['snaplen'] = data[16:20]
    pcapHeader['linktype'] = data[20:24]

    fTxt.write("The contents of pcap header are as follows:\n")
    for key in ['magic_number','version_major','version_minor','thiszone','sigfigs','snaplen','linktype']:
        fTxt.write(key + " : " + repr(pcapHeader[key]) + '\n')
    packet_num = 0
    packet_data = []

    pcap_packet_header_list = []
    i = 24

    while (i<len(data)):
        GMTtime = data[i:i + 4]
        MicroTime = data[i + 4:i + 8]
        caplen = data[i + 8:i + 12]
        lens = data[i + 12:i + 16]

        packet_GMTtime = struct.unpack('I', GMTtime)[0]
        packet_GMTtime = timeTrans(packet_GMTtime)
        packet_MicroTime = struct.unpack('I', MicroTime)[0]
        packet_caplen = struct.unpack('I', caplen)[0]
        packet_len = struct.unpack('I', lens)[0]

        head = PcapPacketHeader()
        head.GMTtime = packet_GMTtime
        head.microTime = packet_MicroTime
        head.capLen = packet_caplen
        head.len = packet_len

        pcap_packet_header_list.append(head)
        packet_data.append(data[i + 16:i + 16 + packet_len])
        i = i + packet_len + 16
        packet_num += 1

    for i in range(packet_num):
        fTxt.write("This is the " + str(i) + "th packet's header and data:" + '\n')
        fTxt.write('GMTtime' + ' : ' + repr(pcap_packet_header_list[i].GMTtime) + '\n')
        fTxt.write('MicroTime' + ' : ' + repr(pcap_packet_header_list[i].microTime) + '\n')
        fTxt.write('caplen' + ' : ' + repr(pcap_packet_header_list[i].capLen) + '\n')
        fTxt.write('lens' + ' : ' + repr(pcap_packet_header_list[i].len) + '\n')
        fTxt.write('Data:' + repr(packet_data[i]) + '\n')

    fTxt.write('[+]Total: ' + str(packet_num) + " packets" + '\n')

    fTxt.close()
    fPcap.close()