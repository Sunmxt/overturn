package log

import (
	log "github.com/Sirupsen/logrus"
)

var logger *log.Logger

func init() {
	logger = log.New()
}
