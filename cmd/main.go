package main

import (
	"context"
	"fmt"
	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
	"github.com/rfyiamcool/go-netflow"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cast"
)

var (
	nf netflow.Interface

	yellow  = color.New(color.FgYellow).SprintFunc()
	red     = color.New(color.FgRed).SprintFunc()
	info    = color.New(color.FgGreen).SprintFunc()
	blue    = color.New(color.FgBlue).SprintFunc()
	magenta = color.New(color.FgHiMagenta).SprintFunc()
)

func start() {
	var err error

	nf, err = netflow.New()
	if err != nil {
		log.Fatal(err)
	}

	err = nf.Start()
	if err != nil {
		log.Fatal(err)
	}

	var (
		recentRankLimit = 100

		sigch   = make(chan os.Signal, 1)
		ticker  = time.NewTicker(5 * time.Second)
		timeout = time.NewTimer(300 * time.Second)
	)

	signal.Notify(sigch,
		syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT,
		syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGUSR2,
	)

	defer func() {
		nf.Stop()
	}()

	go func() {
		for {
			<-ticker.C
			rank, err := nf.GetProcessRank(recentRankLimit, 15)
			if err != nil {
				log.Errorf("GetProcessRank failed, err: %s", err.Error())
				continue
			}

			clear()
			var out *netflow.Process
			for _, r := range rank {
				if strings.Contains(r.Exe, "influxdb") {
					out = r
					break
				}
			}
			if out == nil {
				out = &netflow.Process{TrafficStats: &netflow.TrafficStatsEntry{}}
			}
			storeInflux(out)
			showTable(rank)
		}
	}()

	for {
		select {
		case <-sigch:
			return

		case <-timeout.C:
			return
		}
	}
}

func stop() {
	if nf == nil {
		return
	}

	nf.Stop()
}

const thold = 1024 * 1024 // 1mb

func clear() {
	fmt.Printf("\x1b[2J")
}

func storeInflux(process *netflow.Process) {
	userName := "admin"
	password := "admin123"
	// Create a new client using an InfluxDB server base URL and an authentication token
	// For authentication token supply a string in the form: "username:password" as a token. Set empty value for an unauthenticated server
	client := influxdb2.NewClient("http://192.168.1.158:8086", fmt.Sprintf("%s:%s", userName, password))
	// Get the blocking write client
	// Supply a string in the form database/retention-policy as a bucket. Skip retention policy for the default one, use just a database name (without the slash character)
	// Org name is not used
	writeAPI := client.WriteAPIBlocking("", "test/autogen")
	// create point using full params constructor
	for i := 0; i < 100000; i++ {
		p := influxdb2.NewPoint("stat",
			map[string]string{"unit": "流量"},
			map[string]interface{}{"Exe": process.Exe, "Name": process.Name, "in": process.TrafficStats.In, "out": process.TrafficStats.Out,
				"InRate": process.TrafficStats.InRate, "OutRate": process.TrafficStats.OutRate},
			time.Now())
		// Write data
		err := writeAPI.WritePoint(context.Background(), p)
		if err != nil {
			time.Sleep(time.Second)
			fmt.Printf("Write error: %s\n", err.Error())
			continue
		}
		time.Sleep(time.Second)
	}

	// Get query client. Org name is not used
	queryAPI := client.QueryAPI("")
	// Supply string in a form database/retention-policy as a bucket. Skip retention policy for the default one, use just a database name (without the slash character)
	result, err := queryAPI.Query(context.Background(), `from(bucket:"test")|> range(start: -1h) |> filter(fn: (r) => r._measurement == "stat")`)
	if err == nil {
		for result.Next() {
			if result.TableChanged() {
				fmt.Printf("table: %s\n", result.TableMetadata().String())
			}
			fmt.Printf("row: %s\n", result.Record().String())
		}
		if result.Err() != nil {
			fmt.Printf("Query error: %s\n", result.Err().Error())
		}
	} else {
		fmt.Printf("Query error: %s\n", err.Error())
	}
	// Close client
	client.Close()
}

func showTable(ps []*netflow.Process) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"pid", "name", "exe", "inodes", "sum_in", "sum_out", "in_rate", "out_rate"})
	table.SetRowLine(true)

	items := [][]string{}
	for _, po := range ps {
		inRate := humanBytes(po.TrafficStats.InRate)
		if po.TrafficStats.InRate > int64(thold) {
			inRate = red(inRate)
		}

		outRate := humanBytes(po.TrafficStats.OutRate)
		if po.TrafficStats.OutRate > int64(thold) {
			outRate = red(outRate)
		}

		item := []string{
			po.Pid,
			po.Name,
			po.Exe,
			cast.ToString(po.InodeCount),
			humanBytes(po.TrafficStats.In),
			humanBytes(po.TrafficStats.Out),
			inRate + "/s",
			outRate + "/s",
		}

		items = append(items, item)
	}

	table.AppendBulk(items)
	table.Render()
}

func humanBytes(n int64) string {
	return humanize.Bytes(uint64(n))
}

func main() {
	log.Info("start netflow sniffer")

	start()
	stop()

	log.Info("netflow sniffer exit")
}
