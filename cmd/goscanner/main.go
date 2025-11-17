package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/x1thexxx-lgtm/goscanner/pkg/config"
	"github.com/x1thexxx-lgtm/goscanner/pkg/discovery"
	"github.com/x1thexxx-lgtm/goscanner/pkg/fingerprint"
	"github.com/x1thexxx-lgtm/goscanner/pkg/glpi"
	"github.com/x1thexxx-lgtm/goscanner/pkg/inventory"
	"github.com/x1thexxx-lgtm/goscanner/pkg/logging"
)

func main() {
	var configPath string
	var command string
	var rangeFilter string
	flag.StringVar(&configPath, "config", "goscanner.yaml", "path to config file")
	flag.StringVar(&command, "command", "scan", "command to run (scan|list)")
	flag.StringVar(&rangeFilter, "range", "", "CIDR to scan")
	flag.Parse()

	cfg, err := config.Load(configPath)
	if err != nil {
		panic(err)
	}
	logger, err := logging.New(cfg.Logging.Path, logging.ParseLevel(cfg.Logging.Level))
	if err != nil {
		panic(err)
	}

	switch command {
	case "list":
		listRanges(cfg)
	case "scan":
		runScan(cfg, rangeFilter, logger)
	default:
		fmt.Println("unknown command", command)
		os.Exit(1)
	}
}

func listRanges(cfg *config.Config) {
	for _, site := range cfg.Sites {
		fmt.Printf("Site %s\n", site.Name)
		for _, r := range site.Ranges {
			fmt.Printf("  %s (%s)\n", r.CIDR, r.ProfileName)
		}
	}
}

func runScan(cfg *config.Config, rangeFilter string, logger *logging.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	logger.Infof("starting scan run")
	assets := []inventory.AssetModel{}
	fp := fingerprint.NewEngine()
	for _, site := range cfg.Sites {
		logger.Infof("site %s", site.Name)
		for _, r := range site.Ranges {
			if rangeFilter != "" && r.CIDR != rangeFilter {
				continue
			}
			logger.Infof("scanning %s with profile %s", r.CIDR, r.ProfileName)
			profile, ok := cfg.Profiles[r.ProfileName]
			if !ok {
				logger.Errorf("profile %s missing", r.ProfileName)
				continue
			}
			scanner := discovery.NewScanner(profile, logger)
			hosts, err := scanner.ScanCIDR(ctx, r.CIDR)
			if err != nil {
				logger.Errorf("scan error %s: %v", r.CIDR, err)
				continue
			}
			logger.Debugf("%s produced %d host results", r.CIDR, len(hosts))
			for _, host := range hosts {
				if !host.Alive {
					continue
				}
				logger.Debugf("fingerprinting %s with %d open ports", host.IP, len(host.OpenPorts))
				asset := fp.FingerprintHost(ctx, host)
				assets = append(assets, asset)
			}
		}
	}
	if cfg.GLPI.BaseURL != "" {
		maybePromptGLPIPassword(cfg)
		logger.Infof("pushing %d assets to GLPI at %s", len(assets), cfg.GLPI.BaseURL)
		client := glpi.NewClient(cfg.GLPI)
		for _, asset := range assets {
			if err := client.UpsertAsset(ctx, asset); err != nil {
				logger.Errorf("glpi upsert failed for %s: %v", asset.IP, err)
			}
		}
	} else {
		logger.Infof("GLPI integration disabled; discovered assets kept local only")
	}
	logger.Infof("discovered %d assets", len(assets))
	fmt.Printf("discovered %d assets\n", len(assets))
}

func maybePromptGLPIPassword(cfg *config.Config) {
	if cfg == nil || cfg.GLPI.OAuth == nil {
		return
	}
	if cfg.GLPI.OAuth.Password != "" || cfg.GLPI.OAuth.Username == "" {
		return
	}
	fmt.Printf("Enter GLPI password for %s: ", cfg.GLPI.OAuth.Username)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		panic(fmt.Errorf("read GLPI password: %w", err))
	}
	cfg.GLPI.OAuth.Password = strings.TrimSpace(line)
}
