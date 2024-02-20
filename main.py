import os
import sys
import time
import signal
import argparse
import threading
import subprocess
from boofuzz import pedrpc

'''
This is a base monitor class, don't instantiate it.
'''
class TargetMonitor():
    def __init__(self, binary_path):
        self.pid = None
        self.binary_path = binary_path
        self.pid = self.reset_target(5)
        self.should_exit = False
        self.attach(self.pid)
        signal.signal(signal.SIGINT, self.signal_handler)

    '''
    Checks if the target is alive. 
    You might want to redefine this function.
    '''
    def is_target_alive(self, timeout):
        try:
            time.sleep(timeout)
            os.kill(self.pid, 0)
        except OSError:
            return False
        return True

    def attach(self, pid):
        threading.Thread(target=self.monitor_loop).start()
        print('Attached to [%s] -> %s' % (self.pid, self.binary_path))

    '''
    Gets a PID of the target. 
    You might want to redefine this function.
    '''
    def getpid(self, binary_path):
        pid = None
        while pid == None:
            try:
                output = subprocess.check_output(('pidof', binary_path)).decode().replace('\n', '')
                pid = int(output)
            except:
                pass
        return pid

    '''
    Restarts the target. 
    You might want to redefine this function.
    '''
    def reset_target(self, timeout):
        print('\nResetting the target...')
        self.stop_target()
        self.start_target()
        return self.getpid(self.binary_path)

    '''
    A loop that checks whether the target is alive.
    You might want to redefine this function.
    '''
    def monitor_loop(self):
        while self.is_target_alive(0) == True:
            pass

        if self.should_exit == True:
            return
        print('The target is dead!')
        self.pid = self.reset_target(5)
        self.attach(self.pid)

    def signal_handler(self, signal, frame):
        try:
            self.should_exit = True
            self.stop_target()
        finally:
            sys.exit(-1)

    '''
    Stops the target.
    Implement this function in a subclass.
    '''
    def stop_target(self):
        pass

    '''
    Starts the target.
    Implement this function in a subclass.
    '''
    def start_target(self):
        pass

'''
This is the monitor class that is specific to FRRouting.

NOTE: this has been tested on Ubuntu 22.04, make sure to redefine the
stop_target() and start_target() functions to reflect your environment.
'''
class FRRMonitor(TargetMonitor):
    def __init__(self, binary_path='/usr/lib/frr/ospfd'):
        super().__init__(binary_path)

    def stop_target(self):
        command = 'systemctl stop frr'
        subprocess.run(command.split(' '))

    def start_target(self):
        command = 'systemctl start frr'
        subprocess.run(command.split(' '))

'''
This is a very simple RPC server for letting the fuzzer know that the target is down.
'''
class RPCServer(pedrpc.Server):
    def __init__(self, monitor, host, port):
        super().__init__(host, port)
        self.monitor = monitor

    def is_target_alive(self, timeout=0):
        return self.monitor.is_target_alive(timeout)

    def receive_testcase(self, test_suite, index, payload):    
        print('\nPotential crash: [%s -> %s]' % (test_suite, index))    
        print(payload)    
        print('\n')  

if __name__ == '__main__':
    argparser = argparse.ArgumentParser()
    argparser.add_argument('--ip', dest='ip', type=str, required=True, help='Server IP address for the RPC connection')
    argparser.add_argument('--port', dest='port', type=int, required=True, help='Server port for the RPC connection')
    argparser.add_argument('--monitor', dest='monitor_kind', type=str, required=True, help='Target to minitor. Supported targets: (1) \'frr\'')
    args = argparser.parse_args()

    if args.ip != None and args.port != None:
        monitor = None
        if args.monitor_kind.lower() == 'frr':
           monitor = FRRMonitor() 
        else:
            print('The monitor \'%s\' is not supported!' % args.monitor_kind)
            sys.exit(-1)

        rpc_server = RPCServer(monitor=monitor, host=args.ip, port=args.port)
        rpc_server.serve_forever()
