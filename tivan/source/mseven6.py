# SPDX-License-Identifier: GPL-2.0+

import struct

from impacket.dcerpc.v5 import transport, even6
from impacket.dcerpc.v5.epm import hept_map
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY

class Result:
    def __init__(self, conn, handle):
        self._conn = conn
        self._handle = handle

    def __iter__(self):
        return self

    def __next__(self):
        req = even6.EvtRpcQueryNext()
        req['LogQuery'] = self._handle
        req['NumRequestedRecords'] = 1
        req['TimeOutEnd'] = 1000
        req['Flags'] = 0
        resp = self._conn.dce.request(req)

        if resp['NumActualRecords'] > 0:
            offset = resp['EventDataIndices'][0]['Data']
            size = resp['EventDataSizes'][0]['Data']
            return b''.join(resp['ResultBuffer'][offset:offset + size])

class MSEven6:
    def __init__(self, machine, username, password, domain):
        binding = hept_map(machine, even6.MSRPC_UUID_EVEN6, protocol='ncacn_ip_tcp')

        trans = transport.DCERPCTransportFactory(binding)
        trans.set_credentials(username, password, domain)

        self.dce = trans.get_dce_rpc()
        self.dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

    def connect(self):
        self.dce.connect()
        self.dce.bind(even6.MSRPC_UUID_EVEN6)

    def query(self):
        req = even6.EvtRpcRegisterLogQuery()
        req['Path'] = 'Security\x00'
        req['Query'] = '*\x00'
        req['Flags'] = even6.EvtQueryChannelName | even6.EvtReadNewestToOldest

        resp = self.dce.request(req)
        handle = resp['Handle']

        return Result(self, handle)
