import sys
import signal
import argparse
from PyQt5 import Qt
from grc.main_packet_sniffer import main_packet_sniffer


def main():
    parser = argparse.ArgumentParser(description="6TiSCH Packet Sniffer")
    parser.add_argument("-t", "--time", type=float, default=0,
                        help="Runtime in minutes (0 = run until Ctrl+C)")
    args = parser.parse_args()

    qapp = Qt.QApplication(sys.argv)

    tb = main_packet_sniffer()
    tb.start()

    print("\n---------------------------------")
    print("6TiSCH Packet Sniffer Application")
    print("---------------------------------\n")
    print("Packet sniffer started\n")
    print(f"{'Timestamp':26} | {'Frame Type':12} | {'CRC':8} | {'Seq':4} | {'Dest Addr':17} | {'Src Addr':17} | {'PAN ID':6}")
    print("-"*110)

    def stop_tb(*args):
        print("\nStopping packet sniffer...")
        tb.stop()
        tb.wait()
        print("Full sniffing report available at: 6TiSCH-packet-sniffer/data/Database.db")
        print("Packet sniffer stopped.")
        Qt.QApplication.quit()

    signal.signal(signal.SIGINT, lambda *args: stop_tb())
    signal.signal(signal.SIGTERM, lambda *args: stop_tb())

    timer = Qt.QTimer()
    timer.start(500)
    timer.timeout.connect(lambda: None)

    if args.time > 0:
        Qt.QTimer.singleShot(int(args.time * 60 * 1000), stop_tb)

    tb.show()
    qapp.exec_()

if __name__=="__main__":
    main()
