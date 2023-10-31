package ps

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"

	"m7s.live/engine/v4/util"
)

type TCPRTP struct {
	net.Conn
}

func (t *TCPRTP) Start(onRTP func(util.Buffer) error) (err error) {
	reader := bufio.NewReader(t.Conn)
	buffer := make(util.Buffer, 1024)
	headBuf := make([]byte, 14)
	var rtpVer uint8
	var rtpSSRC uint32
	for err == nil {
		if _, err = io.ReadFull(reader, headBuf); err != nil {
			return
		}
		curVer, _, curSSRC := getRTPHeadInfo(headBuf[2:])
		if rtpSSRC == 0 {
			rtpVer = curVer
			rtpSSRC = curSSRC
		} else {
			for curVer != rtpVer || curSSRC != rtpSSRC {
				copy(headBuf, headBuf[1:])
				if _, err = io.ReadFull(reader, headBuf[11:]); err != nil {
					return
				}
				curVer, _, curSSRC = getRTPHeadInfo(headBuf[2:])
			}
		}

		buffer.Relloc(int(binary.BigEndian.Uint16(headBuf[0:2])))
		copy(buffer, headBuf[2:])
		if _, err = io.ReadFull(reader, buffer[12:]); err != nil {
			return
		}

		err = onRTP(buffer)
	}
	return
}

func getRTPHeadInfo(head []byte) (ver uint8, pt uint8, ssrc uint32) {
	ver = head[0] >> 6 & 0x3
	pt = head[1] & 0x7F
	ssrc = binary.BigEndian.Uint32(head[8:12])
	return
}
