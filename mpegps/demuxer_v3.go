package mpegps

import (
	"errors"

	"m7s.live/engine/v4/util"
)

var (
	ErrNotFoundStartCode = errors.New("not found the need start code flag")
	ErrMarkerBit         = errors.New("marker bit value error")
	ErrFormatPack        = errors.New("not package standard")
	ErrParsePakcet       = errors.New("parse ps packet error")
)

/*
 This implement from VLC source code
 notes: https://github.com/videolan/vlc/blob/master/modules/mux/mpeg/bits.h
*/

/*
https://github.com/videolan/vlc/blob/master/modules/demux/mpeg
*/
type DecPSPackage struct {
	systemClockReferenceBase      uint64
	systemClockReferenceExtension uint64
	programMuxRate                uint32
	IOBuffer
	Payload []byte
	PTS     uint32
	DTS     uint32
	EsHandler
	audio MpegPsEsStream
	video MpegPsEsStream
}

func (dec *DecPSPackage) clean() {
	dec.systemClockReferenceBase = 0
	dec.systemClockReferenceExtension = 0
	dec.programMuxRate = 0
	dec.Payload = nil
	dec.PTS = 0
	dec.DTS = 0
}

func (dec *DecPSPackage) ReadPayload() (payload []byte, err error) {
	payloadlen, err := dec.Uint16()
	if err != nil {
		return
	}
	return dec.ReadN(int(payloadlen))
}
func (dec *DecPSPackage) Feed(ps []byte) {
	if len(ps) >= 4 && util.BigEndian.Uint32(ps) == StartCodePS {
		if dec.Len() > 0 {
			dec.Skip(4)
			dec.Read()
			dec.Reset()
		}
		dec.Write(ps)
	} else if dec.Len() > 0 {
		dec.Write(ps)
	}
}

// read the buffer and push video or audio
func (dec *DecPSPackage) Read() error {
again:
	dec.clean()
	if err := dec.Skip(9); err != nil {
		return err
	}

	psl, err := dec.ReadByte()
	if err != nil {
		return err
	}
	psl &= 0x07
	if err = dec.Skip(int(psl)); err != nil {
		return err
	}
	var nextStartCode uint32
	var payload []byte
	var frame MpegPsEsStream
loop:
	for err == nil {
		if nextStartCode, err = dec.Uint32(); err != nil {
			break
		}
		switch nextStartCode {
		case StartCodeSYS:
			dec.ReadPayload()
			//err = dec.decSystemHeader()
		case StartCodeMAP:
			err = dec.decProgramStreamMap()
		case StartCodeVideo:
			payload, err = dec.ReadPayload()
			if err == nil {
				if frame, err = dec.video.parsePESPacket(payload); err == nil && frame.Buffer.Len() > 0 {
					dec.ReceiveVideo(frame)
				}
			}
		case StartCodeAudio:
			payload, err = dec.ReadPayload()
			if err == nil {
				frame, err = dec.audio.parsePESPacket(payload)
				if err == nil && frame.Buffer.Len() > 0 {
					dec.ReceiveAudio(frame)
				}
			}
		case StartCodePS:
			break loop
		default:
			dec.ReadPayload()
		}
	}
	if nextStartCode == StartCodePS {
		// utils.Println(aurora.Red("StartCodePS recursion..."), err)
		goto again
	}
	return err
}

/*
	func (dec *DecPSPackage) decSystemHeader() error {
		syslens, err := dec.Uint16()
		if err != nil {
			return err
		}
		// drop rate video audio bound and lock flag
		syslens -= 6
		if err = dec.Skip(6); err != nil {
			return err
		}

		// ONE WAY: do not to parse the stream  and skip the buffer
		//br.Skip(syslen * 8)

		// TWO WAY: parse every stream info
		for syslens > 0 {
			if nextbits, err := dec.Uint8(); err != nil {
				return err
			} else if (nextbits&0x80)>>7 != 1 {
				break
			}
			if err = dec.Skip(2); err != nil {
				return err
			}
			syslens -= 3
		}
		return nil
	}
*/
func (dec *DecPSPackage) decProgramStreamMap() error {
	psm, err := dec.ReadPayload()
	if err != nil {
		return err
	}
	defer dec.EsHandler.ReceivePSM(psm)
	l := len(psm)
	index := 2
	programStreamInfoLen := util.BigEndian.Uint16(psm[index:])
	index += 2
	index += int(programStreamInfoLen)
	programStreamMapLen := util.BigEndian.Uint16(psm[index:])
	index += 2
	for programStreamMapLen > 0 {
		if l <= index+1 {
			break
		}
		streamType := psm[index]
		index++
		elementaryStreamID := psm[index]
		index++
		if elementaryStreamID >= 0xe0 && elementaryStreamID <= 0xef {
			dec.video.Type = streamType
		} else if elementaryStreamID >= 0xc0 && elementaryStreamID <= 0xdf {
			dec.audio.Type = streamType
		}
		if l <= index+1 {
			break
		}
		elementaryStreamInfoLength := util.BigEndian.Uint16(psm[index:])
		index += 2
		index += int(elementaryStreamInfoLength)
		programStreamMapLen -= 4 + elementaryStreamInfoLength
	}
	return nil
}
