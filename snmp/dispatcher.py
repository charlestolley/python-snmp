__all__ = ["Dispatcher"]

import threading

from snmp.ber import ParseError, decode
from snmp.exception import *
from snmp.message import *
from snmp.pdu import AnyPDU
from snmp.security.levels import noAuthNoPriv
from snmp.transport import *
from snmp.typing import *
from snmp.utils import typename

T = TypeVar("T")
class Dispatcher(TransportListener[T]):
    def __init__(self,
        multiplexor: TransportMultiplexor[T],
    ) -> None:
        self.lock = threading.Lock()
        self.msgProcessors: Dict[
            ProtocolVersion,
            MessageProcessor[Any, Any],
        ] = {}

        self.multiplexor = multiplexor
        self.thread: Optional[threading.Thread] = None

    def addMessageProcessor(self, mp: MessageProcessor[Any, Any]) -> None:
        with self.lock:
            self.msgProcessors[mp.VERSION] = mp

    def connectTransport(self, transport: Transport[T]) -> None:
        domain = transport.DOMAIN

        if self.thread is not None:
            self.multiplexor.stop()
            self.thread.join()

        self.multiplexor.register(transport)
        self.thread = threading.Thread(
            target=self.multiplexor.listen,
            args=(self,)
        )

        self.thread.start()

    def hear(self, transport: Transport[T], address: T, data: bytes) -> None:
        try:
            try:
                msgVersion = VersionOnlyMessage.decode(data).version
            except ParseError:
                return

            with self.lock:
                try:
                    mp = self.msgProcessors[msgVersion]
                except KeyError:
                    return

            try:
                message, handle = mp.prepareDataElements(data)
                handle.push(message)
            except IncomingMessageError:
                return

        except AssertionError:
            pass
        except Exception:
            pass

    def sendPdu(self,
        channel: TransportChannel[T],
        msgVersion: ProtocolVersion,
        pdu: AnyPDU,
        handle: RequestHandle,  # type: ignore[type-arg]
        *args: Any,
        **kwargs: Any,
    ) -> None:
        with self.lock:
            try:
                mp = self.msgProcessors[msgVersion]
            except KeyError as err:
                version = str(ProtocolVersion(msgVersion))
                raise ValueError("{} is not enabled".format(version)) from err

        msg = mp.prepareOutgoingMessage(pdu, handle, *args, **kwargs)
        channel.send(msg)

    def shutdown(self) -> None:
        if self.thread is not None:
            self.multiplexor.stop()
            self.thread.join()

        self.multiplexor.close()
        self.thread = None
