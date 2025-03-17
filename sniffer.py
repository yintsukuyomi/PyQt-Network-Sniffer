import sys
import scapy.all as scapy
import pyqtgraph as pg
import pandas as pd
from PyQt6.QtWidgets import (QApplication, QMainWindow, QTableWidget, QTableWidgetItem, QVBoxLayout, 
                             QWidget, QPushButton, QLineEdit, QLabel, QFileDialog, QComboBox)

from PyQt6.QtCore import QThread, pyqtSignal, QTimer
import datetime

class PacketSnifferThread(QThread):
    packet_captured = pyqtSignal(dict)

    def __init__(self, filter_text, filter_protocol):
        super().__init__()
        self.filter_text = filter_text
        self.filter_protocol = filter_protocol
        self.running = True
        self.packets = []

    def run(self):
        scapy.sniff(prn=self.process_packet, store=False)
    
    def process_packet(self, packet):
        if self.running:
            try:
                src_ip = packet[scapy.IP].src if packet.haslayer(scapy.IP) else "Unknown"
                dst_ip = packet[scapy.IP].dst if packet.haslayer(scapy.IP) else "Unknown"
                protocol = packet[scapy.IP].proto if packet.haslayer(scapy.IP) else "Unknown"
                src_port = packet[scapy.TCP].sport if packet.haslayer(scapy.TCP) else (packet[scapy.UDP].sport if packet.haslayer(scapy.UDP) else "Unknown")
                dst_port = packet[scapy.TCP].dport if packet.haslayer(scapy.TCP) else (packet[scapy.UDP].dport if packet.haslayer(scapy.UDP) else "Unknown")
                size = len(packet)
                timestamp = datetime.datetime.now().strftime('%H:%M:%S')
                
                packet_info = {"Time": timestamp, "Source": f"{src_ip}:{src_port}", "Destination": f"{dst_ip}:{dst_port}", "Protocol": protocol, "Size": size}
                
                # Apply filters
                if self.filter_protocol and self.filter_protocol != protocol:
                    return
                if self.filter_text and not any(self.filter_text.lower() in str(value).lower() for value in packet_info.values()):
                    return
                
                self.packet_captured.emit(packet_info)
                self.packets.append(packet)
            except Exception as e:
                self.packet_captured.emit({"Error": str(e)})

    def stop(self):
        self.running = False

class SnifferApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Advanced Network Sniffer")
        self.setGeometry(100, 100, 1000, 600)
        self.initUI()
        self.sniffer_thread = None
        self.packet_data = []

    def initUI(self):
        layout = QVBoxLayout()
        
        self.filter_label = QLabel("Filter (IP/Port/Protocol):")
        layout.addWidget(self.filter_label)
        
        self.filter_input = QLineEdit()
        layout.addWidget(self.filter_input)
        
        self.protocol_label = QLabel("Filter by Protocol:")
        layout.addWidget(self.protocol_label)
        
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["All", "TCP", "UDP", "ICMP"])
        layout.addWidget(self.protocol_combo)
        
        self.start_button = QPushButton("Start Sniffing")
        self.start_button.clicked.connect(self.start_sniffing)
        layout.addWidget(self.start_button)
        
        self.stop_button = QPushButton("Stop Sniffing")
        self.stop_button.clicked.connect(self.stop_sniffing)
        layout.addWidget(self.stop_button)
        
        self.save_button = QPushButton("Save to PCAP")
        self.save_button.clicked.connect(self.save_pcap)
        layout.addWidget(self.save_button)
        
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(5)
        self.packet_table.setHorizontalHeaderLabels(["Time", "Source", "Destination", "Protocol", "Size"])
        layout.addWidget(self.packet_table)
        
        self.graph_widget = pg.PlotWidget()
        layout.addWidget(self.graph_widget)
        self.graph_data = []
        
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_graph)
        self.timer.start(1000)
        
        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

    def start_sniffing(self):
        filter_text = self.filter_input.text()
        filter_protocol = self.protocol_combo.currentText()
        self.sniffer_thread = PacketSnifferThread(filter_text, filter_protocol)
        self.sniffer_thread.packet_captured.connect(self.display_packet)
        self.sniffer_thread.start()
    
    def stop_sniffing(self):
        if self.sniffer_thread:
            self.sniffer_thread.stop()
            self.sniffer_thread.quit()
            self.sniffer_thread.wait()
            self.sniffer_thread = None

    def display_packet(self, packet):
        if "Error" in packet:
            return
        self.packet_data.append(packet)
        row_count = self.packet_table.rowCount()
        self.packet_table.insertRow(row_count)
        for col, key in enumerate(packet.keys()):
            self.packet_table.setItem(row_count, col, QTableWidgetItem(str(packet[key])))
        self.graph_data.append(len(self.packet_data))

    def update_graph(self):
        self.graph_widget.clear()
        self.graph_widget.plot(self.graph_data, pen='g')

    def save_pcap(self):
        if not self.sniffer_thread or not self.sniffer_thread.packets:
            return
        filename, _ = QFileDialog.getSaveFileName(self, "Save PCAP", "", "PCAP Files (*.pcap)")
        if filename:
            scapy.wrpcap(filename, self.sniffer_thread.packets)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SnifferApp()
    window.show()
    sys.exit(app.exec())

