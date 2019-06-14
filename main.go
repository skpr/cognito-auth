package main

import (
	"github.com/skpr/cognito-auth/cmd"
	"github.com/skpr/cognito-auth/cmd/google"
	"github.com/skpr/cognito-auth/cmd/userpool"
	"gopkg.in/alecthomas/kingpin.v2"
	"os"
)

func main() {

	app := kingpin.New("cognito-auth", "Cognito CLI authentication commands")

	cmdGoogle := app.Command("google", "Google commands").Alias("g")
	google.Login(cmdGoogle)

	cmdUserpool := app.Command("userpool", "Userpool commands").Alias("up")
	userpool.Login(cmdUserpool)
	userpool.Logout(cmdUserpool)
	userpool.ResetPassword(cmdUserpool)

	cmd.ConsoleSignIn(app)

	kingpin.MustParse(app.Parse(os.Args[1:]))
}
