package main

import (
	"fmt"

	"github.com/CortexFoundation/wormhole"
)

func main() {
	wm := wormhole.New()
	ts := wm.BestTrackers()
	fmt.Println(len(ts))
	fmt.Println(ts)
}
