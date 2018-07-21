package common

import (
	"flag"
	"log"
	"os"
)

var (
	logFileName = flag.String("log", "gosocks.log", "Log file name")
)

func InitLog() {
	logFile, _ := os.OpenFile(*logFileName, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0666)
	log.SetFlags(log.Ldate | log.Lshortfile)
	log.SetOutput(logFile)
}
