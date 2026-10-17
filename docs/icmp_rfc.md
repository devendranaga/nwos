# Icmp implementation

## Destination unreachable

To respond with port and protocol unreachable, the upper layer such as the udp / tcp protocols must present to icmp who are the users of the source ports.
If there are no users for these ports, treat them as port unreachable.

If the protocol specified in the ip header is not available, then treat it as protocol unreachable.

Keep this as an API and let the upper layer define the types and pass this to the icmp layer. Icmp layer will then fill this and schedule the message for transport.

## Time exceeded message

If the host receiving the datagram cannot complete the re-assembly in time, it will discard the datagram and sends the time exceeded message.

## source quench

This means that the receiver must detect what speed it can consume before its buffer overflows with too many messages.
The message should come from the receiver of the datagrams. The sender could just be able to parse and report the application to reduce the speed.
