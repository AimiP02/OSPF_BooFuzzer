import time
import random
import argparse
from boofuzz import *
from boofuzz import helpers
from boofuzz import constants
from base.ospf_dd import OSPFDDFuzzer

'''
OSPF DD #1
- 不包含LSA，DD序列号随机
- Options是fuzzable的
'''
class OSPFDDFuzzer_1(OSPFDDFuzzer):

    def __init__(self, router_id, area_id, rhost, rpc_port=1234):
        super().__init__(router_id, area_id, rhost, rpc_port)
        random.seed(time.time())

    def do_fuzz(self):
        PARAM_ROUTER_ID = self.router_id
        PARAM_AREA_ID = self.area_id

        s_initialize('ospf_dd')
        if s_block_start('IP'):
            if s_block_start('IP Header'):
                s_byte(value=0x45, name='Version', fuzzable=False) # IPv4
                s_byte(value=0xC0, name='TOS', fuzzable=False) # TOS
                s_size(block_name='OSPF', length=2, math=lambda x: x + 20, name='Total Length', endian=BIG_ENDIAN, fuzzable=False) # Total Length
                s_word(value=0x0000, name='Identification', fuzzable=False) # Identification
                s_word(value=0x0000, name='Flags & Fragment Offset', fuzzable=False)
                s_byte(value=0x01, name='TTL', fuzzable=False) # TTL
                s_byte(value=0x59, name='Protocol', fuzzable=False) # Protocol OSPF
                s_checksum(name='Checksum', block_name='IP Header', algorithm='ipv4', endian=BIG_ENDIAN, fuzzable=False) # Checksum
                s_dword(value=helpers.ip_str_to_bytes(PARAM_ROUTER_ID), name='Router ID', endian=BIG_ENDIAN, fuzzable=False) # Source IP
                s_dword(value=helpers.ip_str_to_bytes(self.rhost), name='Target IP', endian=BIG_ENDIAN, fuzzable=False) # Target IP
            s_block_end()
            if s_block_start('OSPF'):
                if s_block_start('Header'):
                    s_byte(value=0x02, name='Version', fuzzable=False) # Version OSPFv2
                    s_byte(value=0x02, name='Type', fuzzable=False) # Packet type Database Description
                    s_size(block_name='Database Description', length=2, math=lambda x: x + 24, name='Packet Length', endian=BIG_ENDIAN, fuzzable=False) # Packet Length
                    s_dword(value=helpers.ip_str_to_bytes(PARAM_ROUTER_ID), name='Router ID', endian=BIG_ENDIAN, fuzzable=False) # Router ID
                    s_dword(value=helpers.ip_str_to_bytes(PARAM_AREA_ID), name='Area ID', endian=BIG_ENDIAN, fuzzable=False) # Area ID
                    s_checksum(name='Checksum', block_name='OSPF', algorithm='ipv4', endian=BIG_ENDIAN, fuzzable=False) # Checksum
                    s_word(value=0x0000, name='Autype', endian=BIG_ENDIAN, fuzzable=False) # Autype
                    s_qword(value=0x00000000, name='Authentication', endian=BIG_ENDIAN, fuzzable=False) # Authentication
                s_block_end()
                if s_block_start('Database Description'):
                    s_word(value=1500, name='Interface MTU', endian=BIG_ENDIAN, fuzzable=False) # Interface MTU
                    s_byte(value=0x02, name='Options', endian=BIG_ENDIAN, fuzzable=True) # Options
                    s_byte(value=0x07, name='DB Description', endian=BIG_ENDIAN, fuzzable=False) # DB Description
                    s_dword(name='DD Sequence Number', endian=BIG_ENDIAN, fuzzable=True) # DD Sequence Number
                s_block_end()
            s_block_end()
        s_block_end()

        self.session_handle.connect(s_get('ospf_dd'))
        self.session_handle.fuzz()

'''
OSPF DD #2
- 包含随机LSA，DD序列号随机
- DB Description是fuzzable的
'''
class OSPFDDFuzzer_2(OSPFDDFuzzer):

    def __init__(self, router_id, area_id, rhost, rpc_port=1234):
        super().__init__(router_id, area_id, rhost, rpc_port)
        random.seed(time.time())

    def do_fuzz(self):
        PARAM_ROUTER_ID = self.router_id
        PARAM_AREA_ID = self.area_id

        s_initialize('ospf_dd')
        if s_block_start('IP'):
            if s_block_start('IP Header'):
                s_byte(value=0x45, name='Version', fuzzable=False) # IPv4
                s_byte(value=0xC0, name='TOS', fuzzable=False) # TOS
                s_size(block_name='OSPF', length=2, math=lambda x: x + 20, name='Total Length', endian=BIG_ENDIAN, fuzzable=False) # Total Length
                s_word(value=0x0000, name='Identification', fuzzable=False) # Identification
                s_word(value=0x0000, name='Flags & Fragment Offset', fuzzable=False)
                s_byte(value=0x01, name='TTL', fuzzable=False) # TTL
                s_byte(value=0x59, name='Protocol', fuzzable=False) # Protocol OSPF
                s_checksum(name='Checksum', block_name='IP Header', algorithm='ipv4', endian=BIG_ENDIAN, fuzzable=False) # Checksum
                s_dword(value=helpers.ip_str_to_bytes(PARAM_ROUTER_ID), name='Router ID', endian=BIG_ENDIAN, fuzzable=False) # Source IP
                s_dword(value=helpers.ip_str_to_bytes(self.rhost), name='Target IP', endian=BIG_ENDIAN, fuzzable=False) # Target IP
            s_block_end()
            if s_block_start('OSPF'):
                if s_block_start('Header'):
                    s_byte(value=0x02, name='Version', fuzzable=False) # Version OSPFv2
                    s_byte(value=0x02, name='Type', fuzzable=False) # Packet type Database Description
                    s_size(block_name='Database Description', length=2, math=lambda x: x + 24, name='Packet Length', endian=BIG_ENDIAN, fuzzable=False) # Packet Length
                    s_dword(value=helpers.ip_str_to_bytes(PARAM_ROUTER_ID), name='Router ID', endian=BIG_ENDIAN, fuzzable=False) # Router ID
                    s_dword(value=helpers.ip_str_to_bytes(PARAM_AREA_ID), name='Area ID', endian=BIG_ENDIAN, fuzzable=False) # Area ID
                    s_checksum(name='Checksum', block_name='OSPF', algorithm='ipv4', endian=BIG_ENDIAN, fuzzable=False) # Checksum
                    s_word(value=0x0000, name='Autype', endian=BIG_ENDIAN, fuzzable=False) # Autype
                    s_qword(value=0x00000000, name='Authentication', endian=BIG_ENDIAN, fuzzable=False) # Authentication
                s_block_end()
                if s_block_start('Database Description'):
                    s_word(value=1500, name='Interface MTU', endian=BIG_ENDIAN, fuzzable=False) # Interface MTU
                    s_byte(value=0x02, name='Options', endian=BIG_ENDIAN, fuzzable=False) # Options
                    s_byte(value=0x07, name='DB Description', endian=BIG_ENDIAN, fuzzable=True) # DB Description
                    s_dword(name='DD Sequence Number', endian=BIG_ENDIAN, fuzzable=True) # DD Sequence Number
                    num_lsa = random.randint(1, 10)
                    for num in range(num_lsa):
                        if s_block_start(f'LSA Header - {num}'):
                            s_word(value=0x0001, name='LS Age', endian=BIG_ENDIAN, fuzzable=False) # LS Age
                            s_byte(value=0x02, name='Options', fuzzable=False) # Options
                            s_byte(value=random.randint(1, 7), name='LS Type', fuzzable=False) # LS Type
                            s_dword(value=helpers.ip_str_to_bytes(PARAM_ROUTER_ID), name='Link State ID', endian=BIG_ENDIAN, fuzzable=False)
                            s_dword(value=helpers.ip_str_to_bytes(PARAM_ROUTER_ID), name='Advertising Router', endian=BIG_ENDIAN, fuzzable=False)
                            s_dword(name='LS Sequence Number', endian=BIG_ENDIAN, fuzzable=True) # DD Sequence Number
                            s_checksum(name='Checksum', block_name=f'LSA Header - {num}', algorithm='ipv4', endian=BIG_ENDIAN, fuzzable=False) # LS Checksum
                            s_size(block_name=f'LSA Header - {num}', length=2, math=lambda x: x + 20, name='Length', endian=BIG_ENDIAN, fuzzable=False)
                        s_block_end()
                s_block_end()
            s_block_end()
        s_block_end()

        self.session_handle.connect(s_get('ospf_dd'))
        self.session_handle.fuzz()

'''
OSPF DD #3
- 包含随机LSA，DD序列号随机
- LSA Header中Options是fuzzable的
'''
class OSPFDDFuzzer_3(OSPFDDFuzzer):

    def __init__(self, router_id, area_id, rhost, rpc_port=1234):
        super().__init__(router_id, area_id, rhost, rpc_port)
        random.seed(time.time())

    def do_fuzz(self):
        PARAM_ROUTER_ID = self.router_id
        PARAM_AREA_ID = self.area_id

        s_initialize('ospf_dd')
        if s_block_start('IP'):
            if s_block_start('IP Header'):
                s_byte(value=0x45, name='Version', fuzzable=False) # IPv4
                s_byte(value=0xC0, name='TOS', fuzzable=False) # TOS
                s_size(block_name='OSPF', length=2, math=lambda x: x + 20, name='Total Length', endian=BIG_ENDIAN, fuzzable=False) # Total Length
                s_word(value=0x0000, name='Identification', fuzzable=False) # Identification
                s_word(value=0x0000, name='Flags & Fragment Offset', fuzzable=False)
                s_byte(value=0x01, name='TTL', fuzzable=False) # TTL
                s_byte(value=0x59, name='Protocol', fuzzable=False) # Protocol OSPF
                s_checksum(name='Checksum', block_name='IP Header', algorithm='ipv4', endian=BIG_ENDIAN, fuzzable=False) # Checksum
                s_dword(value=helpers.ip_str_to_bytes(PARAM_ROUTER_ID), name='Router ID', endian=BIG_ENDIAN, fuzzable=False) # Source IP
                s_dword(value=helpers.ip_str_to_bytes(self.rhost), name='Target IP', endian=BIG_ENDIAN, fuzzable=False) # Target IP
            s_block_end()
            if s_block_start('OSPF'):
                if s_block_start('Header'):
                    s_byte(value=0x02, name='Version', fuzzable=False) # Version OSPFv2
                    s_byte(value=0x02, name='Type', fuzzable=False) # Packet type Database Description
                    s_size(block_name='Database Description', length=2, math=lambda x: x + 24, name='Packet Length', endian=BIG_ENDIAN, fuzzable=False) # Packet Length
                    s_dword(value=helpers.ip_str_to_bytes(PARAM_ROUTER_ID), name='Router ID', endian=BIG_ENDIAN, fuzzable=False) # Router ID
                    s_dword(value=helpers.ip_str_to_bytes(PARAM_AREA_ID), name='Area ID', endian=BIG_ENDIAN, fuzzable=False) # Area ID
                    s_checksum(name='Checksum', block_name='OSPF', algorithm='ipv4', endian=BIG_ENDIAN, fuzzable=False) # Checksum
                    s_word(value=0x0000, name='Autype', endian=BIG_ENDIAN, fuzzable=False) # Autype
                    s_qword(value=0x00000000, name='Authentication', endian=BIG_ENDIAN, fuzzable=False) # Authentication
                s_block_end()
                if s_block_start('Database Description'):
                    s_word(value=1500, name='Interface MTU', endian=BIG_ENDIAN, fuzzable=False) # Interface MTU
                    s_byte(value=0x02, name='Options', endian=BIG_ENDIAN, fuzzable=False) # Options
                    s_byte(value=0x07, name='DB Description', endian=BIG_ENDIAN, fuzzable=False) # DB Description
                    s_dword(name='DD Sequence Number', endian=BIG_ENDIAN, fuzzable=True) # DD Sequence Number
                    num_lsa = random.randint(1, 10)
                    for num in range(num_lsa):
                        if s_block_start(f'LSA Header - {num}'):
                            s_word(value=0x0001, name='LS Age', endian=BIG_ENDIAN, fuzzable=False) # LS Age
                            s_byte(value=0x02, name='Options', fuzzable=True) # Options
                            s_byte(value=random.randint(1, 7), name='LS Type', fuzzable=False) # LS Type
                            s_dword(value=helpers.ip_str_to_bytes(PARAM_ROUTER_ID), name='Link State ID', endian=BIG_ENDIAN, fuzzable=False)
                            s_dword(value=helpers.ip_str_to_bytes(PARAM_ROUTER_ID), name='Advertising Router', endian=BIG_ENDIAN, fuzzable=False)
                            s_dword(name='LS Sequence Number', endian=BIG_ENDIAN, fuzzable=True) # DD Sequence Number
                            s_checksum(name='Checksum', block_name=f'LSA Header - {num}', algorithm='ipv4', endian=BIG_ENDIAN, fuzzable=False) # LS Checksum
                            s_size(block_name=f'LSA Header - {num}', length=2, math=lambda x: x + 20, name='Length', endian=BIG_ENDIAN, fuzzable=False)
                        s_block_end()
                s_block_end()
            s_block_end()
        s_block_end()

        self.session_handle.connect(s_get('ospf_dd'))
        self.session_handle.fuzz()

'''
OSPF DD #4
- 包含随机LSA，DD序列号随机
- Link State ID，Advertising Router 随机
'''
class OSPFDDFuzzer_4(OSPFDDFuzzer):

    def __init__(self, router_id, area_id, rhost, rpc_port=1234):
        super().__init__(router_id, area_id, rhost, rpc_port)
        random.seed(time.time())

    def do_fuzz(self):
        PARAM_ROUTER_ID = self.router_id
        PARAM_AREA_ID = self.area_id

        s_initialize('ospf_dd')
        if s_block_start('IP'):
            if s_block_start('IP Header'):
                s_byte(value=0x45, name='Version', fuzzable=False) # IPv4
                s_byte(value=0xC0, name='TOS', fuzzable=False) # TOS
                s_size(block_name='OSPF', length=2, math=lambda x: x + 20, name='Total Length', endian=BIG_ENDIAN, fuzzable=False) # Total Length
                s_word(value=0x0000, name='Identification', fuzzable=False) # Identification
                s_word(value=0x0000, name='Flags & Fragment Offset', fuzzable=False)
                s_byte(value=0x01, name='TTL', fuzzable=False) # TTL
                s_byte(value=0x59, name='Protocol', fuzzable=False) # Protocol OSPF
                s_checksum(name='Checksum', block_name='IP Header', algorithm='ipv4', endian=BIG_ENDIAN, fuzzable=False) # Checksum
                s_dword(value=helpers.ip_str_to_bytes(PARAM_ROUTER_ID), name='Router ID', endian=BIG_ENDIAN, fuzzable=False) # Source IP
                s_dword(value=helpers.ip_str_to_bytes(self.rhost), name='Target IP', endian=BIG_ENDIAN, fuzzable=False) # Target IP
            s_block_end()
            if s_block_start('OSPF'):
                if s_block_start('Header'):
                    s_byte(value=0x02, name='Version', fuzzable=False) # Version OSPFv2
                    s_byte(value=0x02, name='Type', fuzzable=False) # Packet type Database Description
                    s_size(block_name='Database Description', length=2, math=lambda x: x + 24, name='Packet Length', endian=BIG_ENDIAN, fuzzable=False) # Packet Length
                    s_dword(value=helpers.ip_str_to_bytes(PARAM_ROUTER_ID), name='Router ID', endian=BIG_ENDIAN, fuzzable=False) # Router ID
                    s_dword(value=helpers.ip_str_to_bytes(PARAM_AREA_ID), name='Area ID', endian=BIG_ENDIAN, fuzzable=False) # Area ID
                    s_checksum(name='Checksum', block_name='OSPF', algorithm='ipv4', endian=BIG_ENDIAN, fuzzable=False) # Checksum
                    s_word(value=0x0000, name='Autype', endian=BIG_ENDIAN, fuzzable=False) # Autype
                    s_qword(value=0x00000000, name='Authentication', endian=BIG_ENDIAN, fuzzable=False) # Authentication
                s_block_end()
                if s_block_start('Database Description'):
                    s_word(value=1500, name='Interface MTU', endian=BIG_ENDIAN, fuzzable=False) # Interface MTU
                    s_byte(value=0x02, name='Options', endian=BIG_ENDIAN, fuzzable=False) # Options
                    s_byte(value=0x07, name='DB Description', endian=BIG_ENDIAN, fuzzable=False) # DB Description
                    s_dword(name='DD Sequence Number', endian=BIG_ENDIAN, fuzzable=True) # DD Sequence Number
                    num_lsa = random.randint(1, 10)
                    for num in range(num_lsa):
                        if s_block_start(f'LSA Header - {num}'):
                            s_word(value=0x0001, name='LS Age', endian=BIG_ENDIAN, fuzzable=False) # LS Age
                            s_byte(value=0x02, name='Options', fuzzable=False) # Options
                            s_byte(value=random.randint(1, 7), name='LS Type', fuzzable=False) # LS Type
                            s_dword(name='Link State ID', endian=BIG_ENDIAN, fuzzable=True) # Link State ID
                            s_dword(name='Advertising Router', endian=BIG_ENDIAN, fuzzable=True) # Advertising Router
                            s_dword(name='LS Sequence Number', endian=BIG_ENDIAN, fuzzable=True) # DD Sequence Number
                            s_checksum(name='Checksum', block_name=f'LSA Header - {num}', algorithm='ipv4', endian=BIG_ENDIAN, fuzzable=False) # LS Checksum
                            s_size(block_name=f'LSA Header - {num}', length=2, math=lambda x: x + 20, name='Length', endian=BIG_ENDIAN, fuzzable=False)
                        s_block_end()
                s_block_end()
            s_block_end()
        s_block_end()

        self.session_handle.connect(s_get('ospf_dd'))
        self.session_handle.fuzz()

'''
OSPF DD #5
- LSA random生成
'''
class OSPFDDFuzzer_5(OSPFDDFuzzer):

    def __init__(self, router_id, area_id, rhost, rpc_port=1234):
        super().__init__(router_id, area_id, rhost, rpc_port)
        random.seed(time.time())

    def do_fuzz(self):
        PARAM_ROUTER_ID = self.router_id
        PARAM_AREA_ID = self.area_id

        s_initialize('ospf_dd')
        if s_block_start('IP'):
            if s_block_start('IP Header'):
                s_byte(value=0x45, name='Version', fuzzable=False) # IPv4
                s_byte(value=0xC0, name='TOS', fuzzable=False) # TOS
                s_size(block_name='OSPF', length=2, math=lambda x: x + 20, name='Total Length', endian=BIG_ENDIAN, fuzzable=False) # Total Length
                s_word(value=0x0000, name='Identification', fuzzable=False) # Identification
                s_word(value=0x0000, name='Flags & Fragment Offset', fuzzable=False)
                s_byte(value=0x01, name='TTL', fuzzable=False) # TTL
                s_byte(value=0x59, name='Protocol', fuzzable=False) # Protocol OSPF
                s_checksum(name='Checksum', block_name='IP Header', algorithm='ipv4', endian=BIG_ENDIAN, fuzzable=False) # Checksum
                s_dword(value=helpers.ip_str_to_bytes(PARAM_ROUTER_ID), name='Router ID', endian=BIG_ENDIAN, fuzzable=False) # Source IP
                s_dword(value=helpers.ip_str_to_bytes(self.rhost), name='Target IP', endian=BIG_ENDIAN, fuzzable=False) # Target IP
            s_block_end()
            if s_block_start('OSPF'):
                if s_block_start('Header'):
                    s_byte(value=0x02, name='Version', fuzzable=False) # Version OSPFv2
                    s_byte(value=0x02, name='Type', fuzzable=False) # Packet type Database Description
                    s_size(block_name='Database Description', length=2, math=lambda x: x + 24, name='Packet Length', endian=BIG_ENDIAN, fuzzable=False) # Packet Length
                    s_dword(value=helpers.ip_str_to_bytes(PARAM_ROUTER_ID), name='Router ID', endian=BIG_ENDIAN, fuzzable=False) # Router ID
                    s_dword(value=helpers.ip_str_to_bytes(PARAM_AREA_ID), name='Area ID', endian=BIG_ENDIAN, fuzzable=False) # Area ID
                    s_checksum(name='Checksum', block_name='OSPF', algorithm='ipv4', endian=BIG_ENDIAN, fuzzable=False) # Checksum
                    s_word(value=0x0000, name='Autype', endian=BIG_ENDIAN, fuzzable=False) # Autype
                    s_qword(value=0x00000000, name='Authentication', endian=BIG_ENDIAN, fuzzable=False) # Authentication
                s_block_end()
                if s_block_start('Database Description'):
                    s_word(value=1500, name='Interface MTU', endian=BIG_ENDIAN, fuzzable=False) # Interface MTU
                    s_byte(value=0x02, name='Options', endian=BIG_ENDIAN, fuzzable=False) # Options
                    s_byte(value=0x07, name='DB Description', endian=BIG_ENDIAN, fuzzable=False) # DB Description
                    s_dword(name='DD Sequence Number', endian=BIG_ENDIAN, fuzzable=False) # DD Sequence Number
                    num_lsa = random.randint(1, 10)
                    s_random(name='LSA', min_length=20, max_length=20 * num_lsa, num_mutations=4096, fuzzable=True)
                s_block_end()
            s_block_end()
        s_block_end()

        self.session_handle.connect(s_get('ospf_dd'))
        self.session_handle.fuzz()

'''
Modify this code to choose different test suites and parameters.
'''
if __name__ == '__main__':
    argparser = argparse.ArgumentParser()
    argparser.add_argument('--router_id', dest='router_id', type=str, required=True, help='Router ID')
    argparser.add_argument('--area_id', dest='area_id', type=str, required=True, help='Area ID')
    argparser.add_argument('--tip', dest='tip', type=str, required=True, help='Target IP address')
    argparser.add_argument('--trpc_port', dest='trpc_port', type=int, required=True, default=1234, help='Target RPC port')
    args = argparser.parse_args()

    ROUTER_ID = args.router_id
    AREA_ID = args.area_id
    TIP = args.tip
    TRPC_PORT = args.trpc_port

    '''
    Instantiate and run a test suite
    '''
    fuzzer = OSPFDDFuzzer_1(router_id=ROUTER_ID, area_id=AREA_ID, rhost=TIP, rpc_port=TRPC_PORT)
    # fuzzer = OSPFDDFuzzer_2(router_id=ROUTER_ID, area_id=AREA_ID, rhost=TIP, rpc_port=TRPC_PORT)
    # fuzzer = OSPFDDFuzzer_3(router_id=ROUTER_ID, area_id=AREA_ID, rhost=TIP, rpc_port=TRPC_PORT)
    # fuzzer = OSPFDDFuzzer_4(router_id=ROUTER_ID, area_id=AREA_ID, rhost=TIP, rpc_port=TRPC_PORT)
    # fuzzer = OSPFDDFuzzer_5(router_id=ROUTER_ID, area_id=AREA_ID, rhost=TIP, rpc_port=TRPC_PORT)

    fuzzer.do_fuzz()

    print('Done!')
