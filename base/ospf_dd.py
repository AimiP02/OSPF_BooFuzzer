from base.fuzzer import BaseFuzzer

class OSPFDDFuzzer(BaseFuzzer):
    def __init__(self, ospf_id, rhost, rpc_port=1234, rport='179', hold_time=240):
        super().__init__(ospf_id, rhost, rpc_port, rport, hold_time)
    
    def do_fuzz(self):
        pass