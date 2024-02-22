import time
import random
import argparse
from boofuzz import *
from boofuzz import helpers
from boofuzz import constants
from base.ospf_hello import OSPFHelloFuzzerBase

'''
OSPF Hello #1


'''

class OSPFHelloFuzzer_1(OSPFHelloFuzzerBase):

    def __init__(self, router_id, area_id, rhost, rpc_port=1234):
        super().__init__(router_id, area_id, rhost, rpc_port)
        random.seed(time.time())

    def do_fuzz(self):
        PARAM_ROUTER_ID = self.router_id
        PARAM_AREA_ID = self.area_id

        s_initialize('ospf_hello')
        if s_block_start('OSPF'):
            if s_block_start('Header'):
                s_byte(value=0x02, name='Version', fuzzable=False) # Version OSPFv2
                s_byte(value=0x01, name='Type', fuzzable=False) # Packet type Hello
                s_size(block_name='Hello', length=2, math=lambda x: x + 20, name='Packet Length', fuzzable=False) # Packet Length
                s_dword(value=helpers.ip_str_to_bytes(PARAM_ROUTER_ID), name='Router ID', endian=BIG_ENDIAN, fuzzable=False) # Router ID
                s_dword(value=helpers.ip_str_to_bytes(PARAM_AREA_ID), name='Area ID', endian=BIG_ENDIAN, fuzzable=False) # Area ID
                s_checksum(name='Checksum', block_name='OSPF', algorithm='ipv4', endian=BIG_ENDIAN, fuzzable=False) # Checksum
                s_word(value=0x0000, name='Autype', endian=BIG_ENDIAN, fuzzable=False) # Autype
                s_dword(value=0x00000000, name='Authentication', endian=BIG_ENDIAN, fuzzable=False) # Authentication
            s_block_end()
            if s_block_start('Hello'):
                s_dword(value=helpers.ip_str_to_bytes('255.255.255.0'), name='Network Mask', endian=BIG_ENDIAN, fuzzable=False) # Network Mask
                s_word(value=10, name='HelloInterval', endian=BIG_ENDIAN, fuzzable=False) # HelloInterval
                s_byte(value=0x02, name='Options', endian=BIG_ENDIAN, fuzzable=False) # options
                s_byte(value=0x01, name='Router Priority', endian=BIG_ENDIAN, fuzzable=False) # Router Priority
                s_dword(value=40, name='Router Dead Interval', endian=BIG_ENDIAN, fuzzable=False) # Router Dead Interval
                # Designated Router
                # Backup Designated Router
            s_block_end()
        s_block_end()

        self.session_handle.connect(s_get('ospf_hello'))
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
    fuzzer = OSPFHelloFuzzer_1(router_id=ROUTER_ID, area_id=AREA_ID, rhost=TIP, rpc_port=TRPC_PORT)

    fuzzer.do_fuzz()
