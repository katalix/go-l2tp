package main

import (
	"fmt"
	"golang.org/x/sys/unix"
)

type pppChannel struct {
	pppoxSk      int
	pppSk        int
	channelIndex int
}

func newPPPChannel(pppoxSk int) (c *pppChannel, err error) {

	idx, err := unix.IoctlGetUint32(pppoxSk, unix.PPPIOCGCHAN)
	if err != nil {
		return nil, fmt.Errorf("failed to get pppox channel index: %v", err)
	}

	pppSk, err := unix.Open("/dev/ppp", unix.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open /dev/ppp: %v", err)
	}

	err = unix.IoctlSetPointerInt(pppSk, unix.PPPIOCATTCHAN, int(idx))
	if err != nil {
		unix.Close(pppSk)
		return nil, fmt.Errorf("failed to attach to channel %v: %v", idx, err)
	}

	return &pppChannel{
		pppoxSk:      pppoxSk,
		pppSk:        pppSk,
		channelIndex: int(idx),
	}, nil
}

func (c *pppChannel) bridge(to *pppChannel) (err error) {
	/* FIXME: not upstream yet! */
	var PPPIOCBRIDGECHAN uint = 0x40047435

	err = unix.IoctlSetPointerInt(c.pppSk, PPPIOCBRIDGECHAN, to.channelIndex)
	if err != nil {
		return fmt.Errorf("failed to bridge ppp channels: %v", err)
	}

	err = unix.IoctlSetPointerInt(to.pppSk, PPPIOCBRIDGECHAN, c.channelIndex)
	if err != nil {
		return fmt.Errorf("failed to bridge ppp channels: %v", err)
	}

	return nil
}

func (c *pppChannel) close() {
	if c != nil {
		if c.pppoxSk >= 0 {
			unix.Close(c.pppoxSk)
		}
		if c.pppSk >= 0 {
			unix.Close(c.pppSk)
		}
	}
}
