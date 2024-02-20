from boofuzz import *

'''
The base class for all fuzzers.
'''
class BaseFuzzer():
    def __init__(self, ospf_id, rhost, rpc_port=1234, rport='179', hold_time=240):
        self.ospf_id = ospf_id
        self.rhost = rhost
        self.hold_time = hold_time
        self.rport = int(rport)
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
