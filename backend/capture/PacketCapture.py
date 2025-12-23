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
import logging

from scapy.packet import Packet
from scapy.sendrecv import sniff

from backend.utils.interface_detect import select_interface


class PacketCapture:
    """
    A class for capturing and network packets using Scapy.
    """

    def __init__(self, max_queue_size: int = 100000) -> None:
        """
        CTOR for the PacketCapture instance.
        """

        # create a queue to store captured packets
        # max size to prevent OOM
        self.packet_queue = queue.Queue(maxsize=max_queue_size)

        # threading event controls when to stop capture
        self.stop_capture = threading.Event()

    def packet_callback(self, packet: Packet) -> None:
        """
        Handler for each captured packet. 
        Attempts to push the packet to the queue immediately.
        
        Note: We rely on the BPF filter in start_capture() to ensure 
        only TCP traffic reaches this callback, avoiding expensive 
        Python-side layer checks.

        Args:
            packet (Packet): The raw Scapy packet object.
        """

        # instantly add packet to the queue for process
        try:
            raw_bytes = bytes(packet)
            timestamp = float(packet.time)
            bytes_fmt = (raw_bytes,timestamp)
            self.packet_queue.put_nowait(bytes_fmt)
        except queue.Full:
                logging.warning("Packet queue is full. Dropping packet.")

    def start_capture(self, interface = None, timeout: int = None) -> None:
        """
        Starts the packet capture in a background daemon thread.
        
        Uses BPF (Berkeley Packet Filters) to strictly filter for TCP traffic 
        at the kernel level, optimizing performance by discarding UDP/ICMP 
        before they reach user-space.

        Args:
            interface (str, optional): The network interface to sniff (e.g., 'eth0', 'wlan0'). 
                                     Defaults to "eth0".
            timeout (int, optional): Auto-stop capture after N seconds. Defaults to None (run forever).
        """
        if interface is None:
            self.interface = select_interface()
        else:
            self.interface = interface
        def capture_thread():
            """
            Method to run Scapy's sniff function
            allowing for continuous monitoring of
            the interface for packets.
            """

            try:
                sniff(
                iface=self.interface,
                # procces, defined as func to handle packets
                prn=self.packet_callback,
                # no store in memory
                store=0,
                timeout=timeout,
                # filter packets at kernel level with eBPF
                filter="tcp",
                # stop when stop event set
                stop_filter=lambda _: self.stop_capture.is_set(),
            )
            except Exception as e:
                print(f"Capture thread error : {e}")

        # spawn a separate thread for continuous action
        self.capture_thread = threading.Thread(target=capture_thread, daemon=True)
        self.capture_thread.start()

    def stop_capture_event(self) -> None:
        """
        Method to stop the capture by setting
        a stop capture event and wait for thread
        to finish, allowing clean termination.
        """
        self.stop_capture.set()
        self.capture_thread.join()
