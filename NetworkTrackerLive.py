import pygeoip
import pyshark
from dpkt.utils import mac_to_str
import urllib.request


# This is a databse that we will use to match the IP addresses to real physical locations.
gi = pygeoip.GeoIP('GeoLiteCity.dat')

#This function returns the kml file body.
def retKML(dstip, srcip, pkt_type, number_s, number_r, srcport, dstport):
    dst = gi.record_by_name(dstip)
    src = gi.record_by_name(srcip)
    # Here we extract the longitude and latitude of our IP addresses (source and destination) and insert them into the kml output which is returned.
    try:
        dstlongitude = dst['longitude']
        dstlatitude = dst['latitude']
        srclongitude = src['longitude']
        srclatitude = src['latitude']

        



        kml = (
            '<Placemark>\n'
            '<name>%s</name>\n'
            '<description>%s\nSource Port:%s\nDestination Port:%s\nTotal Number of packets Sent: %s\nTotal Number of Packets Received:%s</description>\n'
            '<extrude>1</extrude>\n'
            '<tessellate>1</tessellate>\n'
            '<styleUrl>#transBluePoly</styleUrl>\n'
            '<LineString>\n'
            '<coordinates>%6f,%6f\n%6f,%6f</coordinates>\n'
            '</LineString>\n'
            '</Placemark>\n'
        )%(dstip, pkt_type, srcport, dstport, number_s, number_r, dstlongitude, dstlatitude, srclongitude, srclatitude)
        return kml
    except:
        return ''
    
# A function that chacks if an ip address has already been visited by us
def not_in(prev_dst, dst):
    for ip in prev_dst:
        if ip == dst:
            return False
    return True

#This function finds the co-ordinates, and other properties of the packet such as protocol, ports etc.
def plotIPs(capture):
    pts = ''
    prev_dst = []
    src = urllib.request.urlopen('https://ident.me').read().decode('utf8')
    for pkt in capture:
        # Here, we capture the source and destination IPs in each packet and send it to the retKML function to find the co-ordinates.
        try:
            dst = pkt.ip.dst
            pkt_type = ""
            if "TCP" in pkt:
                pkt_type = "TCP"
                srcport = pkt.tcp.srcport
                dstport = pkt.tcp.dstport 
            if "UDP" in pkt:
                pkt_type = "UDP"
                srcport = pkt.udp.srcport
                dstport = pkt.udp.dstport
            
            if not_in(prev_dst, dst):
                number_s = 0
                number_r = 0
                for pkt in capture:
                    if pkt.ip.dst == dst:
                        number_s = number_s + 1
                    if pkt.ip.src == dst:
                        number_r = number_r + 1

                kml = retKML(dst,src, pkt_type, number_s, number_r, srcport, dstport)
                prev_dst.append(dst)
            # Co-ordinates are then added to the pts variable and returned.
                pts = pts + kml
        except:
            pass
    return pts

def main():
    #Liive Capture of 450 packets
    capture = pyshark.LiveCapture(interface='Wi-Fi')
    capture.sniff(packet_count=450)

    # We must create a kml document to be accepted by google maps, it will contain 3 variables, 'kmlheader', 'kmlfooter', and in between is the 'pcap' we have after it is run through the plotIPs function.
    kmlheader = '<?xml version="1.0" encoding="UTF-8"?> \n<kml xmlns="http://www.opengis.net/kml/2.2">\n<Document>\n'\
    '<Style id="transBluePoly">'\
    '<LineStyle>'\
    '<width>1</width>'\
    '<color>000000</color>'\
    '</LineStyle>'\
    '</Style>'
    kmlfooter = '</Document>\n'\
    '</kml>\n'
    kmldoc=kmlheader+plotIPs(capture)+kmlfooter
    
    # Creates the kml file itself.
    file = open('KML_Samples.kml', 'w')
    file.writelines(kmldoc)
    file.close()

if __name__ == '__main__':
    main()