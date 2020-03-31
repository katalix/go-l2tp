package l2tp

import (
	"fmt"
)

type fsmCallback func(args []interface{})

type eventDesc struct {
	from, to string
	events   []string
	cb       fsmCallback
}

type fsm struct {
	current string
	table   []eventDesc
}

func (f *fsm) handleEvent(e string, args ...interface{}) error {
	for _, t := range f.table {
		if f.current == t.from {
			for _, event := range t.events {
				if e == event {
					f.current = t.to
					if t.cb != nil {
						t.cb(args)
					}
					return nil
				}
			}
		}
	}
	return fmt.Errorf("no transition defined for event %v in state %v", e, f.current)
}
