from gnuradio import gr
import numpy as np
import sqlite3
import threading
import queue
from datetime import datetime
import atexit

DB_PATH = "/home/konrad/6TiSCH-packet-sniffer/data/Database.db"

class PacketSegmenter(gr.sync_block):
    def __init__(self, access_code='1001000001001110', tag_name='Sync Word', threshold=0, channel="default"):
        gr.sync_block.__init__(self, name="Packet Segmenter", in_sig=[np.uint8], out_sig=[np.uint8])
        self.access_code = np.array([int(b) for b in str(access_code).strip()], dtype=np.uint8)
        self.code_len = len(self.access_code)
        self.threshold = int(threshold)
        self.buffer = np.array([], dtype=np.uint8)
        self.bitrate = 50_000
        self.channel = str(channel)
        self.table_name = "packets_" + "".join(c if c.isalnum() or c == "_" else "_" for c in self.channel)
        self.db_queue = queue.Queue()
        self.db_thread = threading.Thread(target=self._db_worker, daemon=True)
        self.db_thread.start()
        self._init_db()
        self.packet_count = 0
        self.total_packet_time_ms = 0.0
        atexit.register(self._print_final_report)

    def _init_db(self):
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(f'DROP TABLE IF EXISTS {self.table_name}')
        cursor.execute(f'''
            CREATE TABLE {self.table_name} (
                Timestamp TEXT,
                SFD TEXT,
                PHR TEXT,
                FrameType TEXT,
                AckRequest INTEGER,
                DestAddrMode TEXT,
                SrcAddrMode TEXT,
                SeqNum TEXT,
                PAN_ID TEXT,
                DestAddr TEXT,
                SrcAddr TEXT,
                PSDU TEXT,
                CRC_16 TEXT,
                CRC_Check INTEGER,
                PacketDuration_ms REAL
            )
        ''')
        conn.commit()
        conn.close()

    def _db_worker(self):
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        while True:
            row = self.db_queue.get()
            cursor.execute(
                f"INSERT INTO {self.table_name} VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                row
            )
            conn.commit()
            self.db_queue.task_done()

    def _bits_to_hex(self, bits):
        if len(bits) == 0:
            return ""
        val = int(''.join(map(str, bits.tolist())), 2)
        width = ((len(bits) + 7) // 8) * 2
        return f"{val:0{width}X}"

    def _bits_to_bytes_msb(self, bits):
        n = len(bits) // 8
        out = bytearray(n)
        for i in range(n):
            b = 0
            for j in range(8):
                b = (b << 1) | bits[i*8 + j]
            out[i] = b
        return out

    def _clean_hex(self, hex_string):
        while hex_string.startswith("00") and len(hex_string) > 2:
            hex_string = hex_string[2:]
        return hex_string.upper()

    def _reverse_bytes_hex(self, hex_str):
        hex_str = hex_str.upper()
        if len(hex_str) % 2 != 0:
            hex_str = '0' + hex_str
        return ''.join([hex_str[i:i+2] for i in range(0, len(hex_str), 2)][::-1])

    def _parse_fcf(self, fcf_bits):
        fcf_val = int(''.join(map(str, fcf_bits.tolist())), 2)
        fcf_bytes = fcf_val.to_bytes(2, 'big')[::-1]
        fcf_val = int.from_bytes(fcf_bytes, 'big')
        frame_type = fcf_val & 0b111
        ack_request = (fcf_val >> 5) & 1
        dest_addr_mode = (fcf_val >> 10) & 3
        src_addr_mode = (fcf_val >> 14) & 3
        frame_type_map = {0:"Beacon",1:"Data",2:"ACK",3:"MAC Command"}
        addr_mode_map = {0:"None",2:"Short (16-bit)",3:"Long (64-bit)"}
        return frame_type_map.get(frame_type,"Unknown"), ack_request, addr_mode_map.get(dest_addr_mode,"Unknown"), addr_mode_map.get(src_addr_mode,"Unknown"), dest_addr_mode, src_addr_mode

    def _extract_addresses(self, psdu_bits, dest_mode, src_mode):
        idx = 16
        seq_bits = psdu_bits[idx:idx+8]
        idx += 8
        pan_hex = self._reverse_bytes_hex(self._bits_to_hex(psdu_bits[idx:idx+16]))
        idx += 16
        dest_hex = ""
        if dest_mode == 2:
            dest_hex = self._reverse_bytes_hex(self._bits_to_hex(psdu_bits[idx:idx+16]))
            idx += 16
        elif dest_mode == 3:
            dest_hex = self._reverse_bytes_hex(self._bits_to_hex(psdu_bits[idx:idx+64]))
            idx += 64
        src_hex = ""
        if src_mode == 2:
            src_hex = self._reverse_bytes_hex(self._bits_to_hex(psdu_bits[idx:idx+16]))
        elif src_mode == 3:
            src_hex = self._reverse_bytes_hex(self._bits_to_hex(psdu_bits[idx:idx+64]))
        return seq_bits, pan_hex, dest_hex, src_hex

    def _crc16(self, data):
        crc = 0x1D0F
        for b in data:
            crc ^= (b << 8)
            for _ in range(8):
                if crc & 0x8000:
                    crc = ((crc << 1) ^ 0x1021) & 0xFFFF
                else:
                    crc = (crc << 1) & 0xFFFF
        return crc ^ 0xFFFF

    def _print_final_report(self):
        total_time_s = self.total_packet_time_ms / 1000
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sniff_summary (
                Channel TEXT PRIMARY KEY,
                TotalPackets INTEGER,
                TotalTime_s REAL
            )
        ''')

        cursor.execute('''
            INSERT INTO sniff_summary (Channel, TotalPackets, TotalTime_s)
            VALUES (?, ?, ?)
            ON CONFLICT(Channel) DO UPDATE SET
                TotalPackets=excluded.TotalPackets,
                TotalTime_s=excluded.TotalTime_s
        ''', (self.channel, self.packet_count, total_time_s))
        conn.commit()
        conn.close()

    def _save_to_db(self, sfd_bits, phr_bits, psdu_bits):
        sfd_hex = self._bits_to_hex(sfd_bits)
        phr_hex = self._bits_to_hex(phr_bits)
        payload_bits = psdu_bits[:-16]
        crc_bits = psdu_bits[-16:]
        payload_bytes = self._bits_to_bytes_msb(payload_bits)
        crc_rx = self._bits_to_hex(crc_bits)
        data_with_len = bytes([len(payload_bytes)]) + payload_bytes
        crc_check = int(f"{self._crc16(data_with_len):04X}" == crc_rx)
        frame_type = ack = dest_addr_str = src_addr_str = ""
        seq_hex = pan_hex = dest_hex = src_hex = ""
        if len(payload_bits) >= 16:
            frame_type, ack, dest_addr_str, src_addr_str, dest_mode, src_mode = self._parse_fcf(payload_bits[:16])
            seq_bits, pan_hex, dest_hex, src_hex = self._extract_addresses(payload_bits, dest_mode, src_mode)
            seq_hex = self._bits_to_hex(seq_bits)
        packet_bits = len(sfd_bits) + len(phr_bits) + len(psdu_bits)
        packet_duration_ms = (packet_bits / self.bitrate) * 1000
        self.packet_count += 1
        self.total_packet_time_ms += packet_duration_ms
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
        print(f"{timestamp:26} | {frame_type:12} | {'VALID' if crc_check else 'INVALID':8} | {seq_hex:4} | {dest_hex:17} | {src_hex:17} | {pan_hex:6}")
        self.db_queue.put((
            timestamp,
            sfd_hex,
            phr_hex,
            frame_type,
            ack,
            dest_addr_str,
            src_addr_str,
            seq_hex,
            pan_hex,
            dest_hex,
            src_hex,
            payload_bytes.hex().upper(),
            crc_rx,
            crc_check,
            packet_duration_ms
        ))

    def work(self, input_items, output_items):
        in0 = input_items[0].astype(np.uint8)
        out = output_items[0]
        self.buffer = np.concatenate((self.buffer, in0))
        i = 0
        while len(self.buffer) - i >= self.code_len + 8:
            if np.count_nonzero(self.buffer[i:i+self.code_len] ^ self.access_code) <= self.threshold:
                phr_bits = self.buffer[i+self.code_len:i+self.code_len+8]
                psdu_len = int(''.join(map(str, phr_bits.tolist())), 2)
                total_bits = self.code_len + 8 + (psdu_len + 2) * 8
                if len(self.buffer) >= i + total_bits:
                    pkt = self.buffer[i:i+total_bits]
                    self._save_to_db(
                        pkt[:self.code_len],
                        pkt[self.code_len:self.code_len+8],
                        pkt[self.code_len+8:]
                    )
                    i += total_bits
                    continue
                break
            i += 1
        self.buffer = self.buffer[i:]
        out[:len(in0)] = in0
        return len(out)
