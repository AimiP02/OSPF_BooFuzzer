import time
import random
import argparse
from boofuzz import *
from boofuzz import helpers
from boofuzz import constants
from base.ospf_lsu import OSPFLSUFuzzer

'''
OSPF Link State Update
'''

class OSPFLSUFuzzerPacketBase():
    def __init__(self) -> None:
        pass

    def ospf_lsu_packet_dispatch(self, fuzz_enable, ls_type, router_id, packet_index):
        self.router_id = router_id
        self.packet_index = packet_index
        self.fuzz_enable = fuzz_enable
        if ls_type == 1:
            return self.ospf_lsu_packet_router()
        elif ls_type == 2:
            return self.ospf_lsu_packet_network()
        elif ls_type == 3:
            return self.ospf_lsu_packet_summary()
        elif ls_type == 4:
            return self.ospf_lsu_packet_asbr_summary()
        elif ls_type == 5:
            return self.ospf_lsu_packet_as_external()
        elif ls_type == 9 or ls_type == 10 or ls_type == 11:
            return self.ospf_lsu_packet_opaque()

    def ospf_lsu_packet_router(self):
        if s_block_start(f'LSA - {self.packet_index}'):
            s_byte(value=0x00, name='Flags', endian=BIG_ENDIAN, fuzzable=False)
            s_bit_field(value=0x00, name='WVEB', width=4, endian=BIG_ENDIAN, fuzzable=False)
            number_of_links_param = random.randint(1, 10)
            s_word(value=number_of_links_param, name='Number of Links', endian=BIG_ENDIAN, fuzzable=False)
            for link_num in range(0, number_of_links_param):
                if s_block_start(f'Link - {link_num}'):
                    s_dword(value=helpers.ip_str_to_bytes(self.router_id), name='Link ID', endian=BIG_ENDIAN, fuzzable=False)
                    s_dword(value=helpers.ip_str_to_bytes('255.255.255.0'), name='Link Data', endian=BIG_ENDIAN, fuzzable=False)
                    s_byte(value=0x02, name='Link Type', endian=BIG_ENDIAN, fuzzable=False)
                    s_byte(value=0x00, name='TOS', endian=BIG_ENDIAN, fuzzable=False)
                    s_word(value=random.randint(1, 100), name='Metric', endian=BIG_ENDIAN, fuzzable=False)
                s_block_end()
        s_block_end()    

    def ospf_lsu_packet_network(self):           
        if s_block_start(f'LSA - {self.packet_index}'):
            s_dword(value=helpers.ip_str_to_bytes('255.255.255.0'), name='Network Mask', endian=BIG_ENDIAN, fuzzable=False) # Network Mask
            number_of_router = random.randint(1, 10)
            for router_num in range(0, number_of_router):
                s_dword(value=helpers.ip_str_to_bytes(self.router_id), name=f'Attached Router - {router_num}', endian=BIG_ENDIAN, fuzzable=False)
        s_block_end()
    
    def ospf_lsu_packet_summary(self):
        if s_block_start(f'LSA - {self.packet_index}'):
            s_dword(value=helpers.ip_str_to_bytes('255.255.255.0'), name='Network Mask', endian=BIG_ENDIAN, fuzzable=False) # Network Mask
            s_byte(value=0x00, name='Padding - 1', endian=BIG_ENDIAN, fuzzable=False)
            s_bytes(value=b'\x00\x00\x00', size=3, name='metric', fuzzable=False)
            s_byte(value=0x00, name='TOS', endian=BIG_ENDIAN, fuzzable=False)
            s_bytes(value=b'\x00\x00\x00', size=3, name='TOS metric', fuzzable=False)
        s_block_end()
    
    def ospf_lsu_packet_asbr_summary(self):
        if s_block_start(f'LSA - {self.packet_index}'):
            s_dword(value=helpers.ip_str_to_bytes('255.255.255.0'), name='Network Mask', endian=BIG_ENDIAN, fuzzable=False) # Network Mask
            s_byte(value=0x00, name='Padding - 1', endian=BIG_ENDIAN, fuzzable=False)
            s_bytes(value=b'\x00\x00\x00', size=3, name='metric', fuzzable=False)
            s_byte(value=0x00, name='TOS', endian=BIG_ENDIAN, fuzzable=False)
            s_bytes(value=b'\x00\x00\x00', size=3, name='TOS metric', fuzzable=False)
        s_block_end()
    
    def ospf_lsu_packet_as_external(self):
        if s_block_start(f'LSA - {self.packet_index}'):
            s_dword(value=helpers.ip_str_to_bytes('255.255.255.0'), name='Network Mask', endian=BIG_ENDIAN, fuzzable=False) # Network Mask
            number_of_route = random.randint(0, 10)
            for num in range(number_of_route):
                if s_block_start(f'External - {num}'):
                    s_bit(value=0x00, name='E', width=1, endian=BIG_ENDIAN, fuzzable=False)
                    s_bytes(value=b'\x00\x00\x00', size=3, name='metric', fuzzable=False)
                    s_dword(value=helpers.ip_str_to_bytes(self.router_id), name='Forwarding address', endian=BIG_ENDIAN, fuzzable=False) # Forwarding address
                    s_dword(name='External Route Tag', endian=BIG_ENDIAN, fuzzable=False) # External Route Tag
                s_block_end()
        s_block_end()
    
    def ospf_lsu_packet_opaque(self):
        if s_block_start(f'LSA - {self.packet_index}'):
            s_word(value=2, name='Opaque Type', endian=BIG_ENDIAN, fuzzable=False) # Opaque Type
            s_size(block_name=f'sub-TLV - {self.packet_index}', length=2, endian=BIG_ENDIAN, math=lambda x: x + 4, name="Opaque Length", fuzzable=False) # Opaque Length
            if s_block_start(f'sub-TLV - {self.packet_index}'):
                s_word(value=3, name='Opaque Type 1', endian=BIG_ENDIAN, fuzzable=False)
                s_word(value=4, name='Opaque Length 1', endian=BIG_ENDIAN, fuzzable=False)
                s_bytes(value=b'\x00\x00\x00\x00', size=4, name='Opaque Data 1', fuzzable=False)

                s_word(value=3, name='Opaque Type 2', endian=BIG_ENDIAN, fuzzable=False)
                s_word(value=8, name='Opaque Length 2', endian=BIG_ENDIAN, fuzzable=False)
                s_bytes(value=b'\x00\x00\x00\x00', size=4, name='Opaque Data 2.1', fuzzable=False)
                s_bytes(value=b'\x00\x00\x00\x00', size=4, name='Opaque Data 2.2', fuzzable=False)
            s_block_end()
        s_block_end()


class OSPFLSUFuzzer_1(OSPFLSUFuzzer, OSPFLSUFuzzerPacketBase):

    def __init__(self, router_id, area_id, rhost, rpc_port=1234):
        super().__init__(router_id, area_id, rhost, rpc_port)
        random.seed(time.time())

    def do_fuzz(self):
        PARAM_ROUTER_ID = self.router_id
        PARAM_AREA_ID = self.area_id

        s_initialize('ospf_lsu')
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
                    s_byte(value=0x04, name='Type', fuzzable=False) # Packet type Link State Update
                    s_size(block_name='Link State Update', length=2, math=lambda x: x + 24, name='Packet Length', endian=BIG_ENDIAN, fuzzable=False) # Packet Length
                    s_dword(value=helpers.ip_str_to_bytes(PARAM_ROUTER_ID), name='Router ID', endian=BIG_ENDIAN, fuzzable=False) # Router ID
                    s_dword(value=helpers.ip_str_to_bytes(PARAM_AREA_ID), name='Area ID', endian=BIG_ENDIAN, fuzzable=False) # Area ID
                    s_checksum(name='Checksum', block_name='OSPF', algorithm='ipv4', endian=BIG_ENDIAN, fuzzable=False) # Checksum
                    s_word(value=0x0000, name='Autype', endian=BIG_ENDIAN, fuzzable=False) # Autype
                    s_qword(value=0x00000000, name='Authentication', endian=BIG_ENDIAN, fuzzable=False) # Authentication
                s_block_end()
                if s_block_start('Link State Update'):
                    number_of_lsa = 1
                    s_dword(value=number_of_lsa, name='Number of LSAs', endian=BIG_ENDIAN, fuzzable=False) # Number of LSAs
                    for num in range(0, number_of_lsa):
                        if s_block_start(f'LSA Header - {num}'):
                            ls_type = 11
                            s_word(value=0x0001, name='LS Age', endian=BIG_ENDIAN, fuzzable=False) # LS Age
                            s_byte(value=0x02, name='Options', fuzzable=False) # Options
                            s_byte(value=ls_type, name='LS Type', fuzzable=False) # LS Type
                            
                            if ls_type >= 9 and ls_type <= 11:
                                s_byte(value=6, name='Opaque Type', endian=BIG_ENDIAN, fuzzable=False)
                                s_bytes(value=b'\x00\x00\x00', size=3, name='Opaque ID', fuzzable=False)
                            else:
                                s_dword(value=helpers.ip_str_to_bytes(PARAM_ROUTER_ID), name='Link State ID', endian=BIG_ENDIAN, fuzzable=False)
                            
                            s_dword(value=helpers.ip_str_to_bytes(PARAM_ROUTER_ID), name='Advertising Router', endian=BIG_ENDIAN, fuzzable=False)
                            s_dword(value=random.randint(0, 0x80000000), name='LS Sequence Number', endian=BIG_ENDIAN, fuzzable=True)
                            s_checksum(name='Checksum', block_name=f'LSA Header - {num}', algorithm='ipv4', endian=BIG_ENDIAN, fuzzable=False) # LS Checksum
                            s_size(block_name=f'LSA - {num}', length=2, math=lambda x: x + 20, name='Length', endian=BIG_ENDIAN, fuzzable=False)

                            # LSA Start 
                            self.ospf_lsu_packet_dispatch(fuzz_enable=True, ls_type=ls_type, router_id=PARAM_ROUTER_ID, packet_index=num)
                            # LSA End
                        s_block_end()
                s_block_end()
            s_block_end()
        s_block_end()

        self.session_handle.connect(s_get('ospf_lsu'))
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
    fuzzer = OSPFLSUFuzzer_1(router_id=ROUTER_ID, area_id=AREA_ID, rhost=TIP, rpc_port=TRPC_PORT)

    fuzzer.do_fuzz()

    print('Done!')
