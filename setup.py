from setuptools import setup, find_packages

setup(
	name="6TiSCH-packet-sniffer",
	version="0.1",
	description="6TiSCH Packet Sniffer GNU Radio Python blocks",
	packages=find_packages(where="src"),
	package_dir={"": "src"},
        include_package_data=True,
	#install_requires=["gnuradio"],
)
