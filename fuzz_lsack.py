import time
import random
import argparse
from boofuzz import *
from boofuzz import helpers
from boofuzz import constants
from base.ospf_lsack import OSPFLSAckFuzzer

'''
OSPF Link State Acknowledgment
TODO - LSAck also has 5 types packet to response receive packet successfully
- Router-LSA
- Network-LSA
- Summary-LSA
- ASBR-Summary-LSA
- AS-External-LSA
Just change header
'''
class OSPFLSAckFuzzer_1(OSPFLSAckFuzzer):

    def __init__(self, router_id, area_id, rhost, rpc_port=1234):
        super().__init__(router_id, area_id, rhost, rpc_port)
        random.seed(time.time())

    def do_fuzz(self):
        PARAM_ROUTER_ID = self.router_id
        PARAM_AREA_ID = self.area_id

        s_initialize('ospf_lsack')
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
                s_dword(value=helpers.ip_str_to_bytes('224.0.0.5'), name='Target IP', endian=BIG_ENDIAN, fuzzable=False) # Target IP
            s_block_end()
            if s_block_start('OSPF'):
                if s_block_start('Header'):
                    s_byte(value=0x02, name='Version', fuzzable=False) # Version OSPFv2
                    s_byte(value=0x05, name='Type', fuzzable=False) # Packet type Link State Acknowledgment
                    s_size(block_name='Link State Acknowledgment', length=2, math=lambda x: x + 20, name='Packet Length', endian=BIG_ENDIAN, fuzzable=False) # Packet Length
                    s_dword(value=helpers.ip_str_to_bytes(PARAM_ROUTER_ID), name='Router ID', endian=BIG_ENDIAN, fuzzable=False) # Router ID
                    s_dword(value=helpers.ip_str_to_bytes(PARAM_AREA_ID), name='Area ID', endian=BIG_ENDIAN, fuzzable=False) # Area ID
                    s_checksum(name='Checksum', block_name='OSPF', algorithm='ipv4', endian=BIG_ENDIAN, fuzzable=False) # Checksum
                    s_word(value=0x0000, name='Autype', endian=BIG_ENDIAN, fuzzable=False) # Autype
                    s_qword(value=0x00000000, name='Authentication', endian=BIG_ENDIAN, fuzzable=False) # Authentication
                s_block_end()
                if s_block_start('Link State Acknowledgment'):
                    for num in range(0, 5):
                        if s_block_start(f'LSAck Header - {num}'):
                            s_word(value=0x0001, name='LS Age', endian=BIG_ENDIAN, fuzzable=False) # LS Age
                            s_byte(value=0x02, name='Options', fuzzable=False) # Options
                            s_byte(value=random.randint(1, 7), name='LS Type', fuzzable=False) # LS Type
                            s_dword(value=helpers.ip_str_to_bytes(PARAM_ROUTER_ID), name='Link State ID', endian=BIG_ENDIAN, fuzzable=False)
                            s_dword(value=helpers.ip_str_to_bytes(PARAM_ROUTER_ID), name='Advertising Router', endian=BIG_ENDIAN, fuzzable=False)
                            s_dword(value=random.randint(0, 0x80000000), name='LS Sequence Number', endian=BIG_ENDIAN, fuzzable=False)
                            s_checksum(name='Checksum', block_name=f'LSAck Header - {num}', algorithm='ipv4', endian=BIG_ENDIAN, fuzzable=False) # LS Checksum
                            s_size(block_name=f'LSA - {num}', length=2, math=lambda x: x + 20, name='Length', endian=BIG_ENDIAN, fuzzable=False)
                        s_block_end()
                s_block_end()
            s_block_end()
        s_block_end()

        self.session_handle.connect(s_get('ospf_lsack'))
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
    fuzzer = OSPFLSAckFuzzer_1(router_id=ROUTER_ID, area_id=AREA_ID, rhost=TIP, rpc_port=TRPC_PORT)

    fuzzer.do_fuzz()

    print('Done!')
