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
        self._resp = None
        return self

    def __next__(self):
        if self._resp != None and self._resp['NumActualRecords'] == 0:
            return None

        if self._resp == None or self._index == self._resp['NumActualRecords']:
            req = even6.EvtRpcQueryNext()
            req['LogQuery'] = self._handle
            req['NumRequestedRecords'] = 20
            req['TimeOutEnd'] = 1000
            req['Flags'] = 0
            self._resp = self._conn.dce.request(req)

            if self._resp['NumActualRecords'] == 0:
                return None
            else:
                self._index = 0

        offset = self._resp['EventDataIndices'][self._index]['Data']
        size = self._resp['EventDataSizes'][self._index]['Data']
        self._index += 1

        return b''.join(self._resp['ResultBuffer'][offset:offset + size])

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
