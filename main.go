package main

import (
	"github.com/analog-substance/nex/cmd"
	"github.com/analog-substance/util/cli/build_info"
	"github.com/analog-substance/util/cli/updater/cobra_updater"
)

var version = "v0.0.0"
var commit = "replace"

func main() {
	myVersion := build_info.GetVersion(version, commit)

	cmd.RootCmd.Version = myVersion.String()
	cobra_updater.AddToRootCmd(cmd.RootCmd, myVersion)
	cmd.Execute()
}
