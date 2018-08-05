package log

import (
    log "github.com/sirupsen/logrus"
)

var logger *log.Logger

func init() {
    logger = log.New()
}

