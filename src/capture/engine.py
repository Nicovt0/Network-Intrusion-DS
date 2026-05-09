import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from scapy.all import sniff, DNS, DNSQR, IP
from src.capture.flow_manager import FlowManager
# Importarías el orquestador de inferencia aquí más adelante
# from src.ai.inference import InferenceOrchestrator

class SnifferEngine:
    def __init__(self):
        self.flow_manager = FlowManager(max_packets=15, max_time=7)

    def packet_callback(self, pkt):
        # Filtrar solo consultas DNS (QR=0) sobre IP
        if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0 and pkt.haslayer(IP):
            ip_src = pkt[IP].src
            try:
                query_name = pkt[DNSQR].qname.decode('utf-8')
                
                # Intentar agregar al manager y ver si retorna una ventana cerrada
                ventana = self.flow_manager.add_packet(ip_src, query_name)
                
                if ventana:
                    self.send_to_inference(ip_src, ventana)
            except Exception as e:
                print(f"Error procesando paquete: {e}")

    def send_to_inference(self, ip_src, ventana):
        print(f"[!] Ventana lista para {ip_src} - Enviando a Capa L1 (XGBoost)")
        # Aquí llamarías a src/ai/inference.py
        # result = InferenceOrchestrator.predict(ventana)
        print(f"    [+] Dominios capturados: {ventana}\n")

    def start(self, interface=None):
        print("[*] Motor de captura iniciado. Escuchando DNS (Puerto 53)...")
        sniff(filter="udp port 53", prn=self.packet_callback, store=0, iface=interface)

if __name__ == "__main__":
    engine = SnifferEngine()
    engine.start()