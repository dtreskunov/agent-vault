package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/Infisical/agent-vault/internal/gatewayconfig"
	"github.com/Infisical/agent-vault/internal/headless"
	"github.com/Infisical/agent-vault/internal/pidfile"
	"github.com/Infisical/agent-vault/internal/store"
	"github.com/spf13/cobra"
)

var gatewayEnvErr error

func init() {
	serverCmd.Flags().String("env-file", "", "load only AGENT_VAULT_* settings from this file (process environment wins)")
	serverCmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		if gatewayEnvErr != nil {
			return gatewayEnvErr
		}
		host, _ := cmd.Flags().GetString("host")
		detach, _ := cmd.Flags().GetBool("detach")
		stdin, _ := cmd.Flags().GetBool("password-stdin")
		return gatewayconfig.Validate(host, detach, stdin)
	}
	upstreamRotate := agentRotateCmd.RunE
	agentRotateCmd.RunE = func(cmd *cobra.Command, args []string) error {
		if gatewayEnvErr != nil {
			return gatewayEnvErr
		}
		if !gatewayconfig.Headless() || args[0] != headless.AgentName {
			return upstreamRotate(cmd, args)
		}
		if err := gatewayconfig.Validate("127.0.0.1", false, false); err != nil {
			return err
		}
		if pid, err := pidfile.Read(); err == nil && pidfile.IsRunning(pid) {
			return fmt.Errorf("stop the gateway before rotating its bootstrap token")
		}
		path, err := store.DefaultDBPath()
		if err != nil {
			return err
		}
		db, err := store.OpenStore(store.StoreConfig{SQLitePath: path, DatabaseURL: os.Getenv("DATABASE_URL")})
		if err != nil {
			return err
		}
		defer db.Close()
		key, err := unlockOrSetup(cmd, db, false)
		if err != nil {
			return err
		}
		defer key.Wipe()
		if err := headless.Rotate(context.Background(), db); err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Bootstrap token rotated and written to AGENT_VAULT_BOOTSTRAP_TOKEN_FILE.")
		return nil
	}
}

func loadGatewayEnv() {
	path, _ := serverCmd.Flags().GetString("env-file")
	gatewayEnvErr = gatewayconfig.Load(path)
}
