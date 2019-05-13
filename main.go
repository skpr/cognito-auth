package main

import (
	"github.com/previousnext/login/cmd"
	"gopkg.in/alecthomas/kingpin.v2"
	"os"
)

func main() {

	app := kingpin.New("login", "Example Cognito CLI login.")

	cmd.Login(app)
	cmd.ForgotPassword(app)

	kingpin.MustParse(app.Parse(os.Args[1:]))
}
