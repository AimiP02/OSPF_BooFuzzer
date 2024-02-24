from boofuzz import *

'''
The base class for all fuzzers.
'''
class BaseFuzzer():
    def __init__(self, router_id, area_id, rhost, rpc_port=1234):
        self.router_id = router_id
        self.area_id = area_id
        self.rhost = rhost
        self.rport = rpc_port
        self.rpc_client = pedrpc.Client(rhost, int(rpc_port))
        self.fuzz_logger = FuzzLoggerCsv()
        self.session_handle = Session(
            target=Target(
                connection=TCPSocketConnection(
                    host=self.rhost,
                    port=self.rport,
                    send_timeout=5,
                    recv_timeout=5,
                ),
            ),
            fuzz_loggers=[self.fuzz_logger],
            ignore_connection_reset=True,
            receive_data_after_each_request=False,
            receive_data_after_fuzz=True, 
            pre_send_callbacks=[self.wait_for_target],
            post_test_case_callbacks=[self.post_send],
        )


    '''
    This function should implement the relevant parts of the protocol and
    the fuzzload.
    '''
    def do_fuzz(self):
        pass

    '''
    Stalls until the RPC client indicates that the target is alive.
    '''
    def wait_for_target(self, target, fuzz_data_logger, session, *args, **kwargs):
        while self.rpc_client.is_target_alive(0) == False:
            pass

    '''
    This function is called after a test case is sent to the target. Tries
    to approximate which test case / fuzzload caused the target to go down
    and generates a PoC using that fuzzload.
    '''
    def post_send(self, target, fuzz_data_logger, session, *args, **kwargs):
        if self.rpc_client.is_target_alive() == False:
            mutant_index = session.mutant_index-1
            payload = self.get_payload(session, mutant_index)
            self.rpc_client.receive_testcase(type(self).__name__, mutant_index, payload)

    '''
    Gets a fuzzload from the fuzzing session. This function should be
    implemented for each fuzzer separately.
    '''
    def get_payload(self, session, index):
        pass

    ''' 
    Generates a PoC from a given fuzzload. This function should be
    implemented for each fuzzer separately.
    '''
    def generate_poc(self, test_suite, mutant_index, payload):
        pass
