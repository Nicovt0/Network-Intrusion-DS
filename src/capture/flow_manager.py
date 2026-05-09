import time
from collections import deque

class FlowManager:
    def __init__(self, max_packets=15, max_time=7):
        self.max_packets = max_packets
        self.max_time = max_time
        # Diccionario: { 'IP': {'packets': [], 'start_time': 0.0} }
        self.buffer_red = {}

    def add_packet(self, ip_src, query_name):
        timestamp_actual = time.time()

        # Inicializar flujo si la IP es nueva
        if ip_src not in self.buffer_red:
            self.buffer_red[ip_src] = {
                'packets': [],
                'start_time': timestamp_actual
            }

        # Guardar consulta en la lista de la IP
        self.buffer_red[ip_src]['packets'].append(query_name)
        
        # Verificar si se cerró la ventana
        datos_ip = self.buffer_red[ip_src]
        tiempo_transcurrido = timestamp_actual - datos_ip['start_time']

        if len(datos_ip['packets']) >= self.max_packets or tiempo_transcurrido >= self.max_time:
            ventana_para_procesar = datos_ip['packets']
            # Limpiar antes de enviar para evitar bloqueos por tiempo de procesamiento
            del self.buffer_red[ip_src]
            return ventana_para_procesar
        
        return None