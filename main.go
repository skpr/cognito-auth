package main

import (
	"github.com/skpr/cognito-auth/cmd"
	"gopkg.in/alecthomas/kingpin.v2"
	"os"
)

func main() {

	app := kingpin.New("auth", "Example Cognito CLI login.")

	cmd.Login(app)
	cmd.Logout(app)
	cmd.GoogleLogin(app)
	cmd.ForgotPassword(app)
	cmd.ConsoleSignIn(app)

	kingpin.MustParse(app.Parse(os.Args[1:]))
}
