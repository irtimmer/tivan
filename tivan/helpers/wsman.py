# SPDX-License-Identifier: GPL-2.0+

from lxml import etree

NS_SOAP_ENVELOPE = 'http://www.w3.org/2003/05/soap-envelope'
NS_ADDRESSING = 'http://schemas.xmlsoap.org/ws/2004/08/addressing'
NS_WSMAN = 'http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd'
NS_MS_WSMAN = 'http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd'

ADDRESS_ANONYMOUS = 'http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous'

ENVELOPE_ATTRS = {
    'action': etree.QName(NS_ADDRESSING, 'Action'),
    'to': etree.QName(NS_ADDRESSING, 'To'),
    'message_id': etree.QName(NS_ADDRESSING, "MessageID"),
    'relates_to': etree.QName(NS_ADDRESSING, "RelatesTo"),
    'resource_uri': etree.QName(NS_WSMAN, "ResourceURI"),
    'max_envelope_size': etree.QName(NS_WSMAN, "MaxEnvelopeSize"),
    'operation_id': etree.QName(NS_MS_WSMAN, "OperationID"),
    'sequence_id': etree.QName(NS_MS_WSMAN, "SequenceId")
}

class Envelope:
    def __init__(self, data=None, nsmap={}):
        if data != None:
            parser = etree.XMLParser(resolve_entities=False)
            self._envelope = etree.XML(data, parser)
            self._header = self._envelope.find(etree.QName(NS_SOAP_ENVELOPE, 'Header'))
        else:
            self._envelope = etree.Element(etree.QName(NS_SOAP_ENVELOPE, 'Envelope'), nsmap={**{
                's': NS_SOAP_ENVELOPE,
                'a': NS_ADDRESSING,
                'p': NS_MS_WSMAN
            }, **nsmap})

            self._header = etree.SubElement(self._envelope, etree.QName(NS_SOAP_ENVELOPE, 'Header'))
            self._body = etree.SubElement(self._envelope, etree.QName(NS_SOAP_ENVELOPE, 'Body'))

    def __getattr__(self, key):
        if key.startswith('_'):
            return super(Envelope, self).__getattr__(key)

        el = self._header.find(ENVELOPE_ATTRS[key])
        return el.text if el != None else None

    def __setattr__(self, key, value):
        if key.startswith('_'):
            return super(Envelope, self).__setattr__(key, value)

        element = etree.SubElement(self._header, ENVELOPE_ATTRS[key])
        if value != None:
            element.text = value

    def must_understand(self, key, value):
        element = self._header.find(ENVELOPE_ATTRS[key])
        if element != None:
            element.set(etree.QName(NS_SOAP_ENVELOPE, 'mustUnderstand'), 'true' if value else 'false')

    def reply(self, req):
        self.relates_to = req.message_id

        if req.operation_id:
            self.operation_id = req.operation_id
            self.must_understand('operation_id', False)

        if req.sequence_id:
            self.sequence_id = req.sequence_id

    @property
    def body(self):
        return self._body

    @property
    def header(self):
        return self._header

    @property
    def root(self):
        return self._envelope

    def tostring(self, encoding=None):
        return etree.tostring(self._envelope, encoding=encoding, xml_declaration=False)
