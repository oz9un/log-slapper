package network

import (
	"context"
	"sync"
	"syscall"

	"github.com/chifflier/nfqueue-go/nfqueue"
	"github.com/oz9un/log-slapper/pkg/initialize"
)

var q *nfqueue.Queue

// Create NFQUEUE to capture packets:
func ListenPackets(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	//Create go nfqueue
	q = new(nfqueue.Queue)
	//Set callback for queue
	q.SetCallback(queueCallback)
	//Initialize queue
	q.Init()
	//Generic reset for bind
	q.Unbind(syscall.AF_INET)
	q.Bind(syscall.AF_INET)
	//Create nfqueue "0"
	q.CreateQueue(0)

	go func() {
		select {
		case <-ctx.Done():
			// If we receive a signal on the ctx.Done() channel, stop the loop and clean up
			q.StopLoop()
		}
	}()

	q.Loop()
	q.DestroyQueue()
	q.Close()
	initialize.IptablesRemove()
}
