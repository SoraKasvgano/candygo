package app

import (
	"testing"
	"time"

	"candygo/internal/common"
)

func TestClientRunCleansQueuesOnEarlyReturn(t *testing.T) {
	c := newClient()
	c.setWebSocket("invalid-scheme://example.invalid")

	queues := []struct {
		name  string
		queue *MsgQueue
	}{
		{name: "websocket", queue: c.getWsMsgQueue()},
		{name: "tun", queue: c.getTunMsgQueue()},
		{name: "peer", queue: c.getPeerMsgQueue()},
	}
	for _, queue := range queues {
		queue.queue.Write(common.NewMsg(common.PACKET, []byte("stale")))
	}

	c.run()

	type result struct {
		name string
		msg  Msg
	}
	results := make(chan result, len(queues))
	for _, queue := range queues {
		go func(name string, queue *MsgQueue) {
			results <- result{name: name, msg: queue.Read()}
		}(queue.name, queue.queue)
	}

	deadline := time.After(2 * time.Second)
	for range queues {
		select {
		case got := <-results:
			if got.msg.Kind != common.TIMEOUT {
				t.Errorf("%s queue retained message kind %d after early return", got.name, got.msg.Kind)
			}
		case <-deadline:
			t.Fatal("timed out waiting for queue cleanup checks")
		}
	}
}
