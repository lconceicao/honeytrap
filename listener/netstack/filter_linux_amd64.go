// +build netstack

// Copyright 2016-2019 DutchSec (https://dutchsec.com/)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package netstack

import (
	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip/stack"
)

func NewFilter(lower tcpip.LinkEndpointID) tcpip.LinkEndpointID {
	return stack.RegisterLinkEndpoint(&filterEndpoint{
		lower: stack.FindLinkEndpoint(lower),
	})
}

type filterEndpoint struct {
	lower      stack.LinkEndpoint
	dispatcher stack.NetworkDispatcher
}

// WritePacket writes outbound packets to the file descriptor. If it is not
// currently writable, the packet is dropped.
func (e *filterEndpoint) WritePacket(r *stack.Route, gso *stack.GSO, hdr buffer.Prependable, payload buffer.VectorisedView, protocol tcpip.NetworkProtocolNumber) *tcpip.Error {
	// https://godoc.org/golang.org/x/net/bpf
	return e.lower.WritePacket(r, gso, hdr, payload, protocol)
}

// Attach implements the stack.LinkEndpoint interface. It saves the dispatcher
// and registers with the lower filterEndpoint as its dispatcher so that "e" is called
// for inbound packets.
func (e *filterEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
	e.lower.Attach(e)
}

func (e *filterEndpoint) DeliverNetworkPacket(linkEP stack.LinkEndpoint, remoteLinkAddr tcpip.LinkAddress, sourceLinkAddr tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, vv buffer.VectorisedView) {
	e.dispatcher.DeliverNetworkPacket(linkEP, remoteLinkAddr, sourceLinkAddr, protocol, vv)
}

// IsAttached implements stack.LinkEndpoint.IsAttached.
func (e *filterEndpoint) IsAttached() bool {
	return e.dispatcher != nil
}

// MTU implements stack.LinkEndpoint.MTU. It just forwards the request to the
// lower filterEndpoint.
func (e *filterEndpoint) MTU() uint32 {
	return e.lower.MTU()
}

// Capabilities implements stack.LinkEndpoint.Capabilities. It just forwards the
// request to the lower filterEndpoint.
func (e *filterEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return e.lower.Capabilities()
}

// MaxHeaderLength implements the stack.LinkEndpoint interface. It just forwards
// the request to the lower filterEndpoint.
func (e *filterEndpoint) MaxHeaderLength() uint16 {
	return e.lower.MaxHeaderLength()
}

func (e *filterEndpoint) LinkAddress() tcpip.LinkAddress {
	return e.lower.LinkAddress()
}
