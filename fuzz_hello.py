import time
import random
import argparse
from boofuzz import *
from boofuzz import helpers
from boofuzz import constants
from base.ospf_hello import OSPFHelloFuzzerBase

'''
OSPF Hello #1

- BGP header length is correct
- 'Non-Ext OP Len' and 'Non-Ext OP Type' are set to 0xff (extended OPEN)
- Extended Optional parameter length (2 octets) is correct 
- The OPEN message contains between 1 and 4 optional parameters (at random)
- The 'Parameter value' and 'Parameter length' fields are fuzzable
'''
class BgpOpenFuzzer_1(OSPFHelloFuzzerBase):

    def __init__(self, bgp_id, asn_id, rhost, rpc_port=1234, rport='179', hold_time=240):
        super().__init__(bgp_id, asn_id, rhost, rpc_port, rport, hold_time)
        random.seed(time.time())

    def do_fuzz(self):
        PARAM_ASN_ID = self.asn_id
        PARAM_BGP_ID = self.bgp_id
        PARAM_HOLD_TIME = self.hold_time

        s_initialize('bgp_open')
        if s_block_start('BGP'):
            if s_block_start('Header'):
                s_bytes(value=b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF', padding=b'\xFF', size=16, name='Marker', fuzzable=False)
                s_size(block_name='Open', length=2, math=lambda x: x + 19, name='Length', endian=BIG_ENDIAN, fuzzable=False)
                s_byte(value=0x01, endian=BIG_ENDIAN, name='Type', fuzzable=False)
            s_block_end()
            if s_block_start('Open'):
                s_byte(value=0x04, endian=BIG_ENDIAN, name='version', fuzzable=False)
                s_word(value=PARAM_ASN_ID, endian=BIG_ENDIAN, name='ASN', fuzzable=False)
                s_word(value=PARAM_HOLD_TIME, endian=BIG_ENDIAN, name='Hold Time', fuzzable=False)
                s_dword(value=helpers.ip_str_to_bytes(PARAM_BGP_ID), endian=BIG_ENDIAN, name='BGP Identifier', fuzzable=False)
                s_byte(value=b'\xff', endian='>', name='Non-Ext OP Len', fuzzable=False)
                s_byte(value=b'\xff', endian='>', name = 'Non-Ext OP Type', fuzzable=False)
                s_size(block_name='Optional Parameters', length=2, name='Extended Opt. Parm Length', endian=BIG_ENDIAN, fuzzable=False)
                if s_block_start('Optional Parameters'):
                    for param_i in range(random.randint(1, 5)):
                        if s_block_start(f'Reserved {param_i}'):
                            s_byte(value=0x00, endian=BIG_ENDIAN, name='Parameter Type', fuzzable=False)
                            s_size(block_name=f'Reserved Parameter Value {param_i}', length=1, name='Parameter Length', endian=BIG_ENDIAN, fuzzable=True)
                            s_string(value='', name=f'Reserved Parameter Value {param_i}', padding=b'\x00', fuzzable=True, max_len=1500)
                        s_block_end()
                s_block_end()
            s_block_end()
        s_block_end()

        s_initialize('bgp_keepalive')
        if s_block_start('BGP'):
            if s_block_start('Header'):
                s_bytes(value=b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF', padding=b'\xFF', size=16, name='Marker', fuzzable=False)
                s_size(block_name='Keepalive', length=2, math=lambda x: x + 19, name='Length', endian=BIG_ENDIAN, fuzzable=False)
                s_byte(value=0x04, endian=BIG_ENDIAN, name='Type', fuzzable=False)
            s_block_end()
            if s_block_start('Keepalive'):
                pass
            s_block_end()
        s_block_end()

        self.session_handle.connect(s_get('bgp_open'))
        self.session_handle.connect(s_get('bgp_open'),s_get('bgp_keepalive'))
        self.session_handle.fuzz()

'''
Modify this code to choose different test suites and parameters.
'''
if __name__ == '__main__':
    '''
    Set the parameters
    '''
    argparser = argparse.ArgumentParser()
    argparser.add_argument('--fbgp_id', dest='fbgp_id', type=str, required=True, help='Fuzzer BGP ID.')
    argparser.add_argument('--fasn', dest='fasn', type=int, required=True, default=2, help='Fuzzer ASN number.')
    argparser.add_argument('--tip', dest='tip', type=str, required=True, help='Target IP address.')
    argparser.add_argument('--trpc_port', dest='trpc_port', type=int, required=True, default=1234, help='Target RPC port.')
    args = argparser.parse_args()

    FBGP_ID = args.fbgp_id
    FASN = args.fasn
    TIP = args.tip
    TRPC_PORT = args.trpc_port

    '''
    Instantiate and run a test suite
    '''
    fuzzer = BgpOpenFuzzer_1(bgp_id=FBGP_ID, asn_id=FASN, rhost=TIP, rpc_port=TRPC_PORT)
    #fuzzer = BgpOpenFuzzer_2(bgp_id=FBGP_ID, asn_id=FASN, rhost=TIP, rpc_port=TRPC_PORT)
    #fuzzer = BgpOpenFuzzer_3(bgp_id=FBGP_ID, asn_id=FASN, rhost=TIP, rpc_port=TRPC_PORT)
    #fuzzer = BgpOpenFuzzer_4(bgp_id=FBGP_ID, asn_id=FASN, rhost=TIP, rpc_port=TRPC_PORT)
    #fuzzer = BgpOpenFuzzer_5(bgp_id=FBGP_ID, asn_id=FASN, rhost=TIP, rpc_port=TRPC_PORT)
    #fuzzer = BgpOpenFuzzer_6(bgp_id=FBGP_ID, asn_id=FASN, rhost=TIP, rpc_port=TRPC_PORT)
    fuzzer.do_fuzz()
