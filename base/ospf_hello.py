from base.fuzzer import BaseFuzzer

class OSPFHelloFuzzerBase(BaseFuzzer):
    def __init__(self, router_id, area_id, rhost, rpc_port=1234):
        super().__init__(router_id, area_id, rhost, rpc_port)
    
    def do_fuzz(self):
        pass

    def get_payload(self, session, index):
        data = None
        payload = None
        data = session.test_case_data(index)
        if data != None:
            for step in data.steps:
                if step.type == 'send':
                    payload = step.data
                    break
        return payload