package common

type ProxyState int

const (
	STATE_NONE  ProxyState = -1
	STATE_AUTH  ProxyState = 1
	STATE_PROXY ProxyState = 2
)
