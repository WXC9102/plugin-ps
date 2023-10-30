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
    remoteAddr := t.Conn.RemoteAddr().String()
	os.MkdirAll("./rtp", 0766)
	rtpfile, err := os.OpenFile(fmt.Sprintf("./rtp/%s", remoteAddr), os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer rtpfile.Close()

	reader := bufio.NewReader(t.Conn)
	buffer := make(util.Buffer, 1024)
	headBuf := make([]byte, 14)
	var rtpVer uint8
	var rtpPT uint8
	var rtpSSRC uint32
	for err == nil {
		if _, err = io.ReadFull(reader, headBuf); err != nil {
			return
		}

        rtpfile.Write(headBuf)
		rtpfile.WriteString("\n")

		curVer, curPT, curSSRC := getRTPHeadInfo(headBuf[2:])
		if rtpSSRC == 0 {
			rtpVer = curVer
			rtpPT = curPT
			rtpSSRC = curSSRC
		} else {
            rtpfile.WriteString(fmt.Sprintf("ver=%d,pt=%d,ssrc=%d, curVer=%d,curPt=%d,curSSRC=%d\n",
				rtpVer, rtpPT, rtpSSRC, curVer, curPT, curSSRC))
			for curVer != rtpVer || curPT != rtpPT || curSSRC != rtpSSRC {
				copy(headBuf, headBuf[1:])
				if _, err = io.ReadFull(reader, headBuf[11:]); err != nil {
					return
				}
				curVer, curPT, curSSRC = getRTPHeadInfo(headBuf[2:])
                rtpfile.WriteString(fmt.Sprintf("curVer=%d,curPt=%d,curSSRC=%d\n",
					curVer, curPT, curSSRC))
			}
		}

		buffer.Relloc(int(binary.BigEndian.Uint16(headBuf[0:2])))
		copy(buffer, headBuf[2:])
		if _, err = io.ReadFull(reader, buffer[12:]); err != nil {
			return
		}

        rtpfile.Write(headBuf[0:2])
        rtpfile.WriteString("  ")
		rtpfile.Write(buffer)
		rtpfile.WriteString("\n\n")

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
