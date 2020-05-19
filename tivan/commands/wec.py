# SPDX-License-Identifier: GPL-2.0+

import click
import uuid
import configparser

from flask import Flask
from flask import request, make_response

from lxml.builder import ElementMaker
from lxml import etree

from parser.sldc import SLDC
from helpers.wsman import Envelope, NS_SOAP_ENVELOPE, NS_ADDRESSING, NS_MS_WSMAN, NS_WSMAN, ADDRESS_ANONYMOUS

NS_ENUMERATION = 'http://schemas.xmlsoap.org/ws/2004/09/enumeration'
NS_EVENTING = 'http://schemas.xmlsoap.org/ws/2004/08/eventing'
NS_POLICY = 'http://schemas.xmlsoap.org/ws/2002/12/policy'

NS_SUBSCRIPTION = 'http://schemas.microsoft.com/wbem/wsman/1/subscription'
NS_AUTH = 'http://schemas.microsoft.com/wbem/wsman/1/authentication'

NS_XSI = "http://www.w3.org/2001/XMLSchema-instance"
NS_XML = "http://www.w3.org/XML/1998/namespace"

RESOURCE_EVENTLOG = 'http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog'

ACTION_ENUMERATE = 'http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate'
ACTION_ENUMERATE_RESPONSE = 'http://schemas.xmlsoap.org/ws/2004/09/enumeration/EnumerateResponse'
ACTION_SUBSCRIBE = 'http://schemas.xmlsoap.org/ws/2004/08/eventing/Subscribe'
ACTION_ACK = 'http://schemas.dmtf.org/wbem/wsman/1/wsman/Ack'
ACTION_END = 'http://schemas.microsoft.com/wbem/wsman/1/wsman/End'

MODE_EVENTS = 'http://schemas.dmtf.org/wbem/wsman/1/wsman/Events'

AUTH_PROFILE_MUTUAL = 'http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual'

FILTER_DIALECT_EVENTQUERY = 'http://schemas.microsoft.com/win/2004/08/events/eventquery'

def handle_sldc():
    if request.content_encoding == 'SLDC':
        request.data = SLDC().decode(request.data)

class WEC:

    def __init__(self, subscriptions):
        self._subscriptions = subscriptions

    def _subscription_to_xml(self, subscription):
        message_id = str(uuid.uuid4()).upper()

        envelope = Envelope(nsmap={
            'e': NS_EVENTING,
            'w': NS_WSMAN,
            'n': NS_ENUMERATION
        })
        envelope.root.set(etree.QName(NS_XML, "lang"), "en-GB")

        envelope.resource_uri = RESOURCE_EVENTLOG
        envelope.message_id = 'uuid:%s' % message_id
        envelope.must_understand('resource_uri', True)
        envelope.to = ADDRESS_ANONYMOUS
        envelope.action = ACTION_SUBSCRIBE
        envelope.must_understand('action', True)
        envelope.operation_id = 'uuid:%s' % str(uuid.uuid4()).upper()
        envelope.sequence_id = '1'
        envelope.max_envelope_size = '512000'
        envelope.must_understand('operation_id', False)
        envelope.must_understand('sequence_id', False)
        envelope.must_understand('max_envelope_size', True)

        A = ElementMaker(namespace=NS_ADDRESSING)
        W = ElementMaker(namespace=NS_WSMAN)
        P = ElementMaker(namespace=NS_MS_WSMAN)
        C = ElementMaker(namespace=NS_POLICY, nsmap={
            'c': NS_POLICY,
            'auth': NS_AUTH
        })
        E = ElementMaker(namespace=NS_EVENTING)
        AUTH = ElementMaker(namespace=NS_AUTH)
        EM = ElementMaker()

        W_NS = ElementMaker(namespace=NS_WSMAN, nsmap={
            'xsi': NS_XSI
        })

        envelope.header.append(A.ReplyTo(
            A.Address({ '{%s}mustUnderstand' % NS_SOAP_ENVELOPE: 'true' }, ADDRESS_ANONYMOUS)
        ))
        envelope.header.append(W.Locale({ '{%s}lang' % NS_XML: 'en-GB', '{%s}mustUnderstand' % NS_SOAP_ENVELOPE: 'false' }))
        envelope.header.append(P.DataLocale({ '{%s}lang' % NS_XML: 'en-GB', '{%s}mustUnderstand' % NS_SOAP_ENVELOPE: 'false' }))

        envelope.header.append(W_NS.OptionSet(
            W.Option({ 'Name': 'SubscriptionName' }, subscription['name']),
            W.Option({ 'Name': 'Compression' }, 'SLDC'),
            W.Option({ 'Name': 'CDATA', '{%s}nil' % NS_XSI: 'true' }),
            W.Option({ 'Name': 'ContentFormat' }, subscription['content_format']),
            W.Option({ 'Name': 'IgnoreChannelError', '{%s}nil' % NS_XSI: 'true' })
        ))

        envelope.body.append(E.Subscribe(
            E.EndTo(
                A.Address(subscription['url']),
                A.ReferenceProperties(
                    E.Identifier(str(subscription['uuid']).upper())
                )
            ),
            E.Delivery(
                { 'Mode': MODE_EVENTS },
                W.Heartbeats(subscription['heartbeat']),
                E.NotifyTo(
                    A.Address(subscription['url']),
                    A.ReferenceProperties(
                        E.Identifier(str(subscription['uuid']).upper())
                    ),
                    C.Policy(
                        C.ExactlyOne(
                            C.All(
                                AUTH.Authentication(
                                    { 'Profile': AUTH_PROFILE_MUTUAL },
                                    AUTH.ClientCertificate(
                                        AUTH.Thumbprint({ 'Role': 'issuer' }, subscription['ca_thumbprint'])
                                    )
                                )
                            )
                        )
                    ),
                ),
                W.ConnectionRetry({ 'Total': str(subscription['connection_retry_total']) }, subscription['connection_retry']),
                W.MaxTime(subscription['max_time']),
                W.MaxEnvelopeSize({ 'Policy': 'Notify' }, '512000'),
                W.Locale({ '{%s}lang' % NS_XML: 'en-GB', '{%s}mustUnderstand' % NS_SOAP_ENVELOPE: 'false' }),
                P.DataLocale({ '{%s}lang' % NS_XML: 'en-GB', '{%s}mustUnderstand' % NS_SOAP_ENVELOPE: 'false' }),
                W.ContentEncoding(subscription['encoding']),
            ),
            W.Filter({ 'Dialect': FILTER_DIALECT_EVENTQUERY }, etree.fromstring(subscription['query'])),
            W.SendBookmarks()
        ))

        M = ElementMaker(namespace=NS_SUBSCRIPTION, nsmap={
            'm': NS_SUBSCRIPTION
        })
        subscription = M.Subscription(
            M.Version('uuid:%s' % str(subscription['uuid']).upper()),
            message_id
        )

        return (envelope, message_id, subscription)

    def subscription(self, subscription, id):
        req = Envelope(request.data.decode('UTF-16'))
        ret = Envelope()
        req.action = ACTION_ACK
        req.to = ADDRESS_ANONYMOUS
        ret.reply(req)

        print(req.tostring('unicode'))

        resp = make_response('', 200)
        resp.headers['Content-Type'] = 'application/soap+xml;charset=UTF-16'
        return resp

    def wec(self):
        req = Envelope(request.data.decode('UTF-16'))
        action = req.action

        if action == ACTION_ENUMERATE:
            N = ElementMaker(namespace=NS_ENUMERATION)
            W = ElementMaker(namespace=NS_WSMAN)
            A = ElementMaker(namespace=NS_ADDRESSING)

            ret = Envelope(nsmap={
                'n': NS_ENUMERATION,
                'w': NS_WSMAN
            })
            ret.action = ACTION_ENUMERATE_RESPONSE
            ret.message_id = 'uuid:%s' % str(uuid.uuid4()).upper()
            ret.to = ADDRESS_ANONYMOUS
            ret.reply(req)

            subscriptions = [self._subscription_to_xml(x) for x in self._subscriptions]
            ret.body.append(N.EnumerateResponse(
                N.EnumerationContext(''),
                W.Items(
                    *map(lambda x: x[2], subscriptions)
                ),
                W.EndOfSequence()
            ))

            ret_string = ret.tostring('unicode')
            for s in subscriptions:
                ret_string = ret_string.replace(s[1], s[0].tostring('unicode'))

            resp = make_response(ret_string.encode('UTF-16'), 200)
            resp.headers['Content-Type'] = 'application/soap+xml;charset=UTF-16'

            return resp

        elif action == ACTION_END:
            resp = make_response('', 204)
            return resp
        else:
            resp = make_response('', 404)
            return resp

@click.command(help='Run WS-Management webserver for WEC')
@click.option('--host', help='Listening IP-address', default='0.0.0.0')
@click.option('--port', help='Listening port', default=5986)
@click.option('--cert', help='Server certificate', required=True)
@click.option('--key', help='Server private key', required=True)
@click.option('--config', help='Configuration file with subscriptions', required=True)
def cli(host, port, cert, key, config):
    cfg = configparser.ConfigParser()
    cfg.read(config)

    subscriptions = list(map(lambda x: {
        'name': x,
        'query': cfg[x]['query'],
        'url': cfg[x]['url'],
        'uuid': uuid.UUID(cfg[x].get('uuid', str(uuid.uuid4()))),
        'ca_thumbprint': cfg[x]['ca_thumbprint'],
        'heartbeat': cfg[x].get('heartbeat', 'PT60.000S'),
        'encoding': cfg[x].get('encoding', 'UTF-16'),
        'content_format': cfg[x].get('content_format', 'RenderedText'),
        'max_time': cfg[x].get('max_time', 'PT60.000S'),
        'connection_retry': cfg[x].get('connection_retry', 'PT10.0S'),
        'connection_retry_total': cfg[x].getint('connection_retry_total', 5)
    }, cfg.sections()))

    app = Flask(__name__)
    app.before_request(handle_sldc)

    w = WEC(subscriptions)

    @app.route("/wsman/SubscriptionManager/WEC", methods=['POST'])
    def wec():
        return w.wec()

    @app.route("/wsman/subscriptions/<string:subscription>/<int:id>", methods=['POST'])
    def subscription(subscription, id):
        return w.subscription(subscription, id)

    app.run(host=host, port=port, ssl_context=(cert, key))
