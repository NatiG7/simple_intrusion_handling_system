"""
- Packet: The base class for all packets in Scapy
    allowing customization and extension of packet structures.
- IP: Used to parse and manipulate IPv4 packets
    extracting source, destination, and protocol information.
- TCP: Handles TCP segments, allowing inspection of sequence numbers
    flags, and ports for deeper traffic analysis.
- sniff: A core function in Scapy that captures packets
    from a specified interface, with optional filters
        for targeted analysis.

Use Case in IPS:
- These imports enable capturing network traffic
    detecting potential threats, and analyzing packet
        headers for anomalies.
- The sniff function will be the entry point for monitoring
    live network activity.
"""

import queue
import threading
from collections import defaultdict

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet
from scapy.sendrecv import sniff


class PacketCapture:
    """
    A class for capturing and analyzing network packets using Scapy.
    """

    def __init__(self):
        """
        CTOR for the PacketCapture instance.
        """

        # create a queue to store captured packets
        self.packet_queue = queue.Queue()
        # TODO different capture queues

        # threading event controls when to stop capture
        self.stop_capture = threading.Event()

    def packet_callback(self, packet: Packet) -> None:
        """
        Method that acts as a handler for each
        captured packet and checks if it contains
        both IP and TCP layers and adds it to the queue.

        Args:
            packet (Packet): The incoming packet that may contain
                                                IP and TCP layers.
        """

        # check packet for ip and tcp layers and add to queue
        if IP in packet and TCP in packet:
            self.packet_queue.put(packet)
        # TODO more packet interception.

    def start_capture(self, interface: str = "eth0") -> None:
        """
        Method to capture packets on a specified interface
        eth0 being the default on most systems as the
        default Ethernet interface. #TODO interfaces dict.

        Args:
            interface (str, optional): The selected interface.
                                            >:Defaults to "eth0".
        """

        def capture_thread():
            """
            Method to run Scapy's sniff function
            allowing for continuous monitoring of
            the interface for packets.
            """

            sniff(
                iface=interface,
                # procces, defined as func to handle packets
                prn=self.packet_callback,
                # no store in memory
                store=0,
                # stop when stop event set
                stop_filter=lambda _: self.stop_capture.is_set(),
            )

        # spawn a separate thread for continuous action
        self.capture_thread = threading.Thread(target=capture_thread)
        self.capture_thread.start()

    def stop_capture_event(self) -> None:
        """
        Method to stop the capture by setting
        a stop capture event and wait for thread
        to finish, allowing clean termination.
        """
        self.stop_capture.set()
        self.capture_thread.join()
